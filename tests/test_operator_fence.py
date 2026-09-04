from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest

import grabowski_operator_fence as fence


INTENT_A = "a" * 64
INTENT_B = "b" * 64
EVIDENCE_A = "c" * 64
EVIDENCE_B = "d" * 64


class Clock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds


class OperatorFenceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "state" / "operator-fence.sqlite3"
        self.clock = Clock()
        self.store = fence.OperatorFenceStore(self.database, clock=self.clock)

    def acquire_primary(self, *, lease_seconds: int = 30) -> dict[str, object]:
        return self.store.acquire(
            owner_id="grabowski",
            session_id="primary-session",
            reason="primary_normal",
            lease_seconds=lease_seconds,
        )

    def begin_primary(self, *, operation_id: str = "op-1") -> dict[str, object]:
        return self.store.begin_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            operation_id=operation_id,
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
        )

    def test_initial_state_has_no_writer_and_generation_zero(self) -> None:
        status = self.store.status()
        self.assertEqual(status["generation"], 0)
        self.assertIsNone(status["writer"])
        self.assertIsNone(status["inflight"])
        self.assertIsNone(status["last_settlement"])

    def test_status_uses_one_explicit_read_transaction(self) -> None:
        real_connection = self.store._connect()
        calls: list[str] = []

        class RecordingConnection:
            def execute(self, statement: str, *args: object, **kwargs: object):
                calls.append(statement.strip().upper())
                return real_connection.execute(statement, *args, **kwargs)

            def close(self) -> None:
                real_connection.close()

        self.store._connect = lambda: RecordingConnection()  # type: ignore[method-assign]
        status = self.store.status()
        self.assertEqual(status["generation"], 0)
        self.assertEqual(calls[0], "BEGIN")
        self.assertEqual(calls[-1], "COMMIT")
        self.assertEqual(calls.count("BEGIN"), 1)
        self.assertEqual(calls.count("COMMIT"), 1)

    def test_acquire_is_single_writer_and_same_session_idempotent(self) -> None:
        first = self.acquire_primary()
        replay = self.acquire_primary()
        self.assertEqual(first["generation"], 1)
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["generation"], 1)
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "writer_active"):
            self.store.acquire(
                owner_id="der-kleine-maulwurf",
                session_id="secondary-session",
                reason="primary_unavailable",
                lease_seconds=30,
            )

    def test_status_never_exposes_raw_session_id(self) -> None:
        self.acquire_primary()
        status = self.store.status()
        writer = status["writer"]
        self.assertIsInstance(writer, dict)
        self.assertNotIn("session_id", writer)
        self.assertEqual(len(writer["session_id_sha256"]), 64)
        self.assertNotIn("primary-session", repr(status))

    def test_expired_grant_reacquire_increments_generation(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.clock.advance(6)
        secondary = self.store.acquire(
            owner_id="der-kleine-maulwurf",
            session_id="secondary-session",
            reason="primary_unavailable",
            lease_seconds=30,
        )
        self.assertEqual(secondary["generation"], 2)
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "stale_generation"):
            self.store.begin_effect(
                owner_id="grabowski",
                session_id="primary-session",
                generation=1,
                operation_id="stale-op",
                operation_name="grabowski_git",
                intent_sha256=INTENT_A,
            )

    def test_expired_grant_cannot_be_renewed(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.clock.advance(5)
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "grant_expired"):
            self.store.renew(
                owner_id="grabowski",
                session_id="primary-session",
                generation=1,
                lease_seconds=30,
            )

    def test_renew_never_shortens_an_active_lease(self) -> None:
        grant = self.acquire_primary(lease_seconds=100)
        self.clock.advance(10)
        status = self.store.renew(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            lease_seconds=5,
        )
        self.assertEqual(
            status["writer"]["lease_until_unix"],
            grant["lease_until_unix"],
        )

    def test_begin_is_idempotent_for_exact_same_intent_only(self) -> None:
        self.acquire_primary()
        first = self.begin_primary()
        replay = self.begin_primary()
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "effect_inflight"):
            self.store.begin_effect(
                owner_id="grabowski",
                session_id="primary-session",
                generation=1,
                operation_id="op-1",
                operation_name="grabowski_git",
                intent_sha256=INTENT_B,
            )

    def test_open_inflight_blocks_takeover_after_writer_lease_expires(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        self.clock.advance(10)
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "unresolved_inflight"):
            self.store.acquire(
                owner_id="der-kleine-maulwurf",
                session_id="secondary-session",
                reason="primary_unavailable",
                lease_seconds=30,
            )
        status = self.store.status()
        self.assertFalse(status["writer"]["lease_active"])
        self.assertEqual(status["inflight"]["state"], "begun")

    def test_outcome_unknown_remains_inflight_and_blocks_takeover(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        result = self.store.settle_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
            outcome="outcome_unknown",
            evidence_sha256=EVIDENCE_A,
        )
        self.assertFalse(result["terminal"])
        self.assertEqual(result["status"]["inflight"]["state"], "outcome_unknown")
        self.clock.advance(10)
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "unresolved_inflight"):
            self.store.acquire(
                owner_id="der-kleine-maulwurf",
                session_id="secondary-session",
                reason="primary_unavailable",
                lease_seconds=30,
            )

    def test_reconcile_unknown_then_secondary_gets_new_generation(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        self.store.settle_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
            outcome="outcome_unknown",
            evidence_sha256=EVIDENCE_A,
        )
        self.clock.advance(10)
        reconciled = self.store.reconcile_effect(
            reconciler_id="der-kleine-maulwurf",
            generation=1,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
            outcome="effect_applied",
            evidence_sha256=EVIDENCE_B,
        )
        self.assertTrue(reconciled["terminal"])
        self.assertIsNone(reconciled["status"]["inflight"])
        self.assertEqual(
            reconciled["status"]["last_settlement"]["resolution_source"],
            "reconcile",
        )
        secondary = self.store.acquire(
            owner_id="der-kleine-maulwurf",
            session_id="secondary-session",
            reason="primary_unavailable",
            lease_seconds=30,
        )
        self.assertEqual(secondary["generation"], 2)

    def test_writer_may_settle_after_lease_expired_but_not_begin_again(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        self.clock.advance(10)
        settled = self.store.settle_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
            outcome="effect_not_applied",
            evidence_sha256=EVIDENCE_A,
        )
        self.assertTrue(settled["terminal"])
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "grant_expired"):
            self.store.begin_effect(
                owner_id="grabowski",
                session_id="primary-session",
                generation=1,
                operation_id="op-2",
                operation_name="grabowski_git",
                intent_sha256=INTENT_B,
            )

    def test_settlement_retry_is_idempotent_and_begin_cannot_replay_it(self) -> None:
        self.acquire_primary()
        self.begin_primary()
        arguments = {
            "owner_id": "grabowski",
            "session_id": "primary-session",
            "generation": 1,
            "operation_id": "op-1",
            "operation_name": "grabowski_git",
            "intent_sha256": INTENT_A,
            "outcome": "effect_applied",
            "evidence_sha256": EVIDENCE_A,
        }
        first = self.store.settle_effect(**arguments)
        replay = self.store.settle_effect(**arguments)
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied, "operation_already_settled"
        ):
            self.begin_primary()

    def test_release_requires_no_unresolved_effect(self) -> None:
        self.acquire_primary()
        self.begin_primary()
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "unresolved_inflight"):
            self.store.release(
                owner_id="grabowski",
                session_id="primary-session",
                generation=1,
            )

    def test_release_then_failback_or_takeover_uses_new_generation(self) -> None:
        self.acquire_primary()
        released = self.store.release(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
        )
        self.assertIsNone(released["writer"])
        secondary = self.store.acquire(
            owner_id="der-kleine-maulwurf",
            session_id="secondary-session",
            reason="controlled_failover_drill",
            lease_seconds=30,
        )
        self.assertEqual(secondary["generation"], 2)

    def test_restart_preserves_generation_and_unresolved_inflight(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
        status = reopened.status()
        self.assertEqual(status["generation"], 1)
        self.assertEqual(status["inflight"]["operation_id"], "op-1")
        self.clock.advance(10)
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "unresolved_inflight"):
            reopened.acquire(
                owner_id="der-kleine-maulwurf",
                session_id="secondary-session",
                reason="primary_unavailable",
                lease_seconds=30,
            )

    def test_concurrent_acquire_has_exactly_one_winner(self) -> None:
        barrier = threading.Barrier(2)

        def attempt(owner: str) -> tuple[str, str | int]:
            barrier.wait(timeout=2)
            try:
                grant = self.store.acquire(
                    owner_id=owner,
                    session_id=f"session-{owner}",
                    reason="controlled_failover_drill",
                    lease_seconds=30,
                )
                return ("granted", int(grant["generation"]))
            except fence.OperatorFenceDenied as exc:
                return ("denied", exc.code)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(
                executor.map(attempt, ["grabowski", "der-kleine-maulwurf"])
            )
        self.assertEqual(sum(item[0] == "granted" for item in results), 1)
        self.assertEqual(sum(item[0] == "denied" for item in results), 1)
        self.assertIn(("denied", "writer_active"), results)
        self.assertEqual(self.store.status()["generation"], 1)

    def test_reconcile_retry_is_idempotent(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        self.store.settle_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
            outcome="outcome_unknown",
            evidence_sha256=EVIDENCE_A,
        )
        arguments = {
            "reconciler_id": "der-kleine-maulwurf",
            "generation": 1,
            "operation_id": "op-1",
            "operation_name": "grabowski_git",
            "intent_sha256": INTENT_A,
            "outcome": "effect_not_applied",
            "evidence_sha256": EVIDENCE_B,
        }
        first = self.store.reconcile_effect(**arguments)
        replay = self.store.reconcile_effect(**arguments)
        self.assertFalse(first["idempotent"])
        self.assertTrue(replay["idempotent"])

    def test_active_begun_effect_cannot_be_reconciled_by_another_caller(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        arguments = {
            "reconciler_id": "der-kleine-maulwurf",
            "generation": 1,
            "operation_id": "op-1",
            "operation_name": "grabowski_git",
            "intent_sha256": INTENT_A,
            "outcome": "effect_not_applied",
            "evidence_sha256": EVIDENCE_B,
        }
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied, "effect_not_reconcilable"
        ):
            self.store.reconcile_effect(**arguments)
        self.clock.advance(6)
        reconciled = self.store.reconcile_effect(**arguments)
        self.assertTrue(reconciled["terminal"])

    def test_settled_operation_id_cannot_replay_under_a_new_generation(self) -> None:
        self.acquire_primary()
        self.begin_primary()
        self.store.settle_effect(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
            operation_id="op-1",
            operation_name="grabowski_git",
            intent_sha256=INTENT_A,
            outcome="effect_applied",
            evidence_sha256=EVIDENCE_A,
        )
        self.store.release(
            owner_id="grabowski",
            session_id="primary-session",
            generation=1,
        )
        secondary = self.store.acquire(
            owner_id="der-kleine-maulwurf",
            session_id="secondary-session",
            reason="primary_unavailable",
            lease_seconds=30,
        )
        self.assertEqual(secondary["generation"], 2)
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied, "operation_already_settled"
        ):
            self.store.begin_effect(
                owner_id="der-kleine-maulwurf",
                session_id="secondary-session",
                generation=2,
                operation_id="op-1",
                operation_name="grabowski_git",
                intent_sha256=INTENT_A,
            )

    def test_database_and_parent_are_private(self) -> None:
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o700)

    def test_invalid_digest_and_lease_bounds_fail_before_state_change(self) -> None:
        with self.assertRaises(ValueError):
            self.store.acquire(
                owner_id="grabowski",
                session_id="primary-session",
                reason="primary_normal",
                lease_seconds=fence.MAX_LEASE_SECONDS + 1,
            )
        self.acquire_primary()
        with self.assertRaises(ValueError):
            self.store.begin_effect(
                owner_id="grabowski",
                session_id="primary-session",
                generation=1,
                operation_id="op-1",
                operation_name="grabowski_git",
                intent_sha256="not-a-digest",
            )
        self.assertIsNone(self.store.status()["inflight"])


if __name__ == "__main__":
    unittest.main()

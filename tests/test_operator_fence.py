from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import multiprocessing
import os
import shutil
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

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


def _process_acquire(
    database: str,
    owner: str,
    barrier: object,
    queue: object,
) -> None:
    store = fence.OperatorFenceStore(Path(database))
    barrier.wait(timeout=5)
    try:
        grant = store.acquire(
            owner_id=owner,
            session_id=f"session-{owner}",
            reason="controlled_failover_drill",
            lease_seconds=30,
        )
        queue.put(("granted", owner, int(grant["generation"])))
    except fence.OperatorFenceDenied as exc:
        queue.put(("denied", owner, exc.code))


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
            "outcome": "effect_applied",
            "evidence_sha256": EVIDENCE_B,
        }
        self.clock.advance(6)
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
            fence.OperatorFenceDenied, "reconcile_requires_expired_writer"
        ):
            self.store.reconcile_effect(**arguments)
        self.clock.advance(6)
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied, "begun_reconcile_requires_typed_proof"
        ):
            self.store.reconcile_effect(**arguments)

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

    def test_multiprocess_acquire_has_exactly_one_winner(self) -> None:
        context = multiprocessing.get_context("fork")
        barrier = context.Barrier(2)
        queue = context.Queue()
        processes = [
            context.Process(
                target=_process_acquire,
                args=(str(self.database), owner, barrier, queue),
            )
            for owner in ("grabowski", "der-kleine-maulwurf")
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(timeout=10)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        results = [queue.get(timeout=2) for _ in processes]
        self.assertEqual(sum(item[0] == "granted" for item in results), 1)
        self.assertEqual(sum(item[0] == "denied" for item in results), 1)
        self.assertEqual({item[2] for item in results}, {1, "writer_active"})
        self.assertEqual(self.store.status()["generation"], 1)

    def test_sqlite_write_lock_fails_closed_with_typed_busy_error(self) -> None:
        locker = sqlite3.connect(self.database, isolation_level=None)
        try:
            locker.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(fence.OperatorFenceError, "SQLite store is busy"):
                self.acquire_primary()
        finally:
            locker.execute("ROLLBACK")
            locker.close()
        self.assertEqual(self.store.status()["generation"], 0)

    def test_database_and_parent_are_private(self) -> None:
        self.assertEqual(self.database.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.database.parent.stat().st_mode & 0o777, 0o700)

    def test_fencing_mark_contains_persistent_instance_identity(self) -> None:
        initial = self.store.status()
        grant = self.acquire_primary()
        self.assertEqual(len(initial["instance_id"]), 32)
        self.assertEqual(grant["instance_id"], initial["instance_id"])
        self.assertEqual(grant["fencing_mark"]["instance_id"], initial["instance_id"])
        reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
        self.assertEqual(reopened.status()["instance_id"], initial["instance_id"])

    def test_session_status_digest_is_keyed_not_plain_sha256(self) -> None:
        self.acquire_primary()
        digest = self.store.status()["writer"]["session_id_sha256"]
        plain = hashlib.sha256(b"primary-session").hexdigest()
        self.assertNotEqual(digest, plain)
        self.assertNotIn(b"primary-session", self.store.session_key_path.read_bytes())

    def test_same_intent_cannot_be_settled_twice_under_new_operation_id(self) -> None:
        self.acquire_primary()
        self.begin_primary()
        self.store.settle_effect(
            owner_id="grabowski", session_id="primary-session", generation=1,
            operation_id="op-1", operation_name="grabowski_git",
            intent_sha256=INTENT_A, outcome="effect_applied",
            evidence_sha256=EVIDENCE_A,
        )
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "intent_already_settled"):
            self.store.begin_effect(
                owner_id="grabowski", session_id="primary-session", generation=1,
                operation_id="op-2", operation_name="grabowski_git",
                intent_sha256=INTENT_A,
            )

    def test_identical_begin_replay_remains_visible_after_lease_expiry(self) -> None:
        self.acquire_primary(lease_seconds=5)
        first = self.begin_primary()
        self.clock.advance(6)
        replay = self.begin_primary()
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["started_at_unix"], first["started_at_unix"])

    def test_settlement_replay_survives_later_generation(self) -> None:
        self.acquire_primary()
        self.begin_primary()
        arguments = {
            "owner_id": "grabowski", "session_id": "primary-session",
            "generation": 1, "operation_id": "op-1",
            "operation_name": "grabowski_git", "intent_sha256": INTENT_A,
            "outcome": "effect_applied", "evidence_sha256": EVIDENCE_A,
        }
        self.store.settle_effect(**arguments)
        self.store.release(
            owner_id="grabowski", session_id="primary-session", generation=1
        )
        self.store.acquire(
            owner_id="der-kleine-maulwurf", session_id="secondary-session",
            reason="primary_unavailable", lease_seconds=30,
        )
        replay = self.store.settle_effect(**arguments)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["recorded_settlement"]["generation"], 1)

    def test_outcome_unknown_persists_evidence_event(self) -> None:
        self.acquire_primary()
        self.begin_primary()
        result = self.store.settle_effect(
            owner_id="grabowski", session_id="primary-session", generation=1,
            operation_id="op-1", operation_name="grabowski_git",
            intent_sha256=INTENT_A, outcome="outcome_unknown",
            evidence_sha256=EVIDENCE_A,
        )
        event = result["status"]["last_event"]
        self.assertEqual(event["event_type"], "outcome_unknown")
        self.assertEqual(event["evidence_sha256"], EVIDENCE_A)
        reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
        self.assertEqual(reopened.status()["last_event"]["evidence_sha256"], EVIDENCE_A)

    def test_fencing_mark_validator_rejects_stale_generation_and_tamper(self) -> None:
        grant = self.acquire_primary()
        token = grant["fencing_mark"]
        validated = self.store.validate_fencing_mark(
            token,
            expected_instance_id=grant["instance_id"],
            minimum_generation_seen=1,
        )
        self.assertEqual(validated, token)
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied, "generation_rollback_detected"
        ):
            self.store.validate_fencing_mark(
                token,
                expected_instance_id=grant["instance_id"],
                minimum_generation_seen=2,
            )
        tampered = dict(token)
        tampered["mark_sha256"] = "0" * 64
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "invalid_fencing_mark"):
            self.store.validate_fencing_mark(
                tampered,
                expected_instance_id=grant["instance_id"],
                minimum_generation_seen=1,
            )

    def test_fencing_mark_is_not_an_authentication_credential(self) -> None:
        grant = self.acquire_primary()
        instance = grant["instance_id"]
        forged_generation = 2**40
        material = {"instance_id": instance, "generation": forged_generation}
        forged = {
            **material,
            "mark_sha256": fence._sha256_json(material),
            "does_not_establish": list(fence.FENCING_MARK_DOES_NOT_ESTABLISH),
        }
        validated = self.store.validate_fencing_mark(
            forged,
            expected_instance_id=instance,
            minimum_generation_seen=1,
        )
        self.assertEqual(validated["generation"], forged_generation)
        self.assertIn("coordinator_authenticity", validated["does_not_establish"])

    def test_forward_clock_jump_cannot_authorize_stale_primary_effect(self) -> None:
        self.acquire_primary(lease_seconds=30)
        self.clock.advance(10_000)
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
                operation_id="late-primary",
                operation_name="grabowski_git",
                intent_sha256=INTENT_A,
            )

    def test_non_application_reconciliation_fails_closed(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        self.store.settle_effect(
            owner_id="grabowski", session_id="primary-session", generation=1,
            operation_id="op-1", operation_name="grabowski_git",
            intent_sha256=INTENT_A, outcome="outcome_unknown",
            evidence_sha256=EVIDENCE_A,
        )
        self.clock.advance(6)
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied,
            "non_application_reconcile_requires_typed_finality_proof",
        ):
            self.store.reconcile_effect(
                reconciler_id="der-kleine-maulwurf", generation=1,
                operation_id="op-1", operation_name="grabowski_git",
                intent_sha256=INTENT_A, outcome="effect_not_applied",
                evidence_sha256=EVIDENCE_B,
            )
        self.assertEqual(self.store.status()["inflight"]["state"], "outcome_unknown")

    def test_backward_clock_denies_mutation_and_surfaces_regression(self) -> None:
        self.acquire_primary(lease_seconds=30)
        self.clock.value -= 1
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "clock_moved_backward"):
            self.store.renew(
                owner_id="grabowski", session_id="primary-session",
                generation=1, lease_seconds=30,
            )
        self.assertTrue(self.store.status()["clock_regressed"])

    def test_database_only_rollback_cannot_reissue_generation(self) -> None:
        first = self.acquire_primary()
        instance = first["instance_id"]
        self.store.release(
            owner_id="grabowski", session_id="primary-session", generation=1
        )
        snapshot = Path(self.temporary.name) / "generation-1.sqlite3"
        shutil.copyfile(self.database, snapshot)
        second = self.store.acquire(
            owner_id="der-kleine-maulwurf", session_id="secondary-session",
            reason="primary_unavailable", lease_seconds=30,
        )
        self.assertEqual(second["generation"], 2)
        self.store.release(
            owner_id="der-kleine-maulwurf", session_id="secondary-session",
            generation=2,
        )
        shutil.copyfile(snapshot, self.database)
        reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
        self.assertEqual(reopened.status()["instance_id"], instance)
        self.assertEqual(reopened.status()["generation"], 2)
        third = reopened.acquire(
            owner_id="grabowski", session_id="primary-session-2",
            reason="failback", lease_seconds=30,
        )
        self.assertEqual(third["generation"], 3)

    def test_full_state_rollback_requires_client_high_water_guard(self) -> None:
        first = self.acquire_primary()
        instance = first["instance_id"]
        self.store.release(
            owner_id="grabowski", session_id="primary-session", generation=1
        )
        snapshot_root = Path(self.temporary.name) / "snapshot"
        snapshot_root.mkdir()
        copies = {}
        for source in (self.database, self.store.anchor_path, self.store.session_key_path):
            target = snapshot_root / source.name
            shutil.copyfile(source, target)
            copies[source] = target
        second = self.store.acquire(
            owner_id="der-kleine-maulwurf", session_id="secondary-session",
            reason="primary_unavailable", lease_seconds=30,
        )
        self.assertEqual(second["generation"], 2)
        self.store.release(
            owner_id="der-kleine-maulwurf", session_id="secondary-session",
            generation=2,
        )
        for target, source in copies.items():
            shutil.copyfile(source, target)
        reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
        with self.assertRaisesRegex(
            fence.OperatorFenceDenied, "generation_rollback_detected"
        ):
            reopened.acquire(
                owner_id="grabowski", session_id="primary-session-2",
                reason="failback", lease_seconds=30,
                expected_instance_id=instance, minimum_generation_seen=2,
            )
        rollback_calls = [
            lambda: reopened.renew(
                owner_id="grabowski", session_id="primary-session", generation=1,
                lease_seconds=30, expected_instance_id=instance,
                minimum_generation_seen=2,
            ),
            lambda: reopened.begin_effect(
                owner_id="grabowski", session_id="primary-session", generation=1,
                operation_id="rollback-begin", operation_name="grabowski_git",
                intent_sha256=INTENT_A, expected_instance_id=instance,
                minimum_generation_seen=2,
            ),
            lambda: reopened.settle_effect(
                owner_id="grabowski", session_id="primary-session", generation=1,
                operation_id="rollback-settle", operation_name="grabowski_git",
                intent_sha256=INTENT_A, outcome="effect_applied",
                evidence_sha256=EVIDENCE_A, expected_instance_id=instance,
                minimum_generation_seen=2,
            ),
            lambda: reopened.reconcile_effect(
                reconciler_id="der-kleine-maulwurf", generation=1,
                operation_id="rollback-reconcile", operation_name="grabowski_git",
                intent_sha256=INTENT_A, outcome="effect_applied",
                evidence_sha256=EVIDENCE_B, expected_instance_id=instance,
                minimum_generation_seen=2,
            ),
            lambda: reopened.release(
                owner_id="grabowski", session_id="primary-session", generation=1,
                expected_instance_id=instance, minimum_generation_seen=2,
            ),
        ]
        for call in rollback_calls:
            with self.assertRaisesRegex(
                fence.OperatorFenceDenied, "generation_rollback_detected"
            ):
                call()
        self.assertEqual(reopened.status()["generation"], 1)

    def test_stale_fence_instance_is_denied(self) -> None:
        self.acquire_primary()
        with self.assertRaisesRegex(fence.OperatorFenceDenied, "stale_fence_instance"):
            self.store.renew(
                owner_id="grabowski", session_id="primary-session", generation=1,
                lease_seconds=30, expected_instance_id="0" * 32,
            )

    def test_writer_disagreement_after_reconcile_is_durable(self) -> None:
        self.acquire_primary(lease_seconds=5)
        self.begin_primary()
        self.store.settle_effect(
            owner_id="grabowski", session_id="primary-session", generation=1,
            operation_id="op-1", operation_name="grabowski_git",
            intent_sha256=INTENT_A, outcome="outcome_unknown",
            evidence_sha256=EVIDENCE_A,
        )
        self.clock.advance(6)
        self.store.reconcile_effect(
            reconciler_id="der-kleine-maulwurf", generation=1,
            operation_id="op-1", operation_name="grabowski_git",
            intent_sha256=INTENT_A, outcome="effect_applied",
            evidence_sha256=EVIDENCE_B,
        )
        disputed = self.store.settle_effect(
            owner_id="grabowski", session_id="primary-session", generation=1,
            operation_id="op-1", operation_name="grabowski_git",
            intent_sha256=INTENT_A, outcome="effect_not_applied",
            evidence_sha256=EVIDENCE_A,
        )
        self.assertTrue(disputed["dispute_recorded"])
        self.assertEqual(disputed["status"]["last_event"]["event_type"], "writer_dispute")

    def test_schema_drift_is_rejected_on_next_connection(self) -> None:
        raw = sqlite3.connect(self.database)
        try:
            raw.execute("CREATE TABLE intruder(value TEXT)")
            raw.commit()
        finally:
            raw.close()
        with self.assertRaisesRegex(fence.OperatorFenceError, "table set"):
            self.store.status()

    def test_database_file_swap_is_detected(self) -> None:
        replacement = Path(self.temporary.name) / "replacement.sqlite3"
        shutil.copyfile(self.database, replacement)
        os.chmod(replacement, 0o600)
        original_inode = self.database.stat().st_ino
        replacement_inode = replacement.stat().st_ino
        self.assertNotEqual(original_inode, replacement_inode)
        os.replace(replacement, self.database)
        with self.assertRaisesRegex(fence.OperatorFenceError, "identity changed"):
            self.store.status()

    def test_reopen_converts_wal_mode_back_to_delete(self) -> None:
        raw = sqlite3.connect(self.database)
        try:
            mode = raw.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self.assertEqual(str(mode).lower(), "wal")
        finally:
            raw.close()
        reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
        connection = sqlite3.connect(self.database)
        try:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(str(mode).lower(), "delete")
        self.assertEqual(reopened.status()["generation"], 0)

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

    def test_reconcile_reads_anchor_only_after_writer_lock(self) -> None:
        acquire_started = threading.Event()
        acquire_done = threading.Event()
        acquire_errors: list[BaseException] = []

        class ReopeningStore(fence.OperatorFenceStore):
            def _load_anchor(inner_self) -> dict[str, object]:
                anchor = super()._load_anchor()

                def acquire_while_reopening() -> None:
                    acquire_started.set()
                    try:
                        self.store.acquire(
                            owner_id="parallel-writer",
                            session_id="parallel-session",
                            reason="parallel_open_race",
                            lease_seconds=30,
                        )
                    except BaseException as exc:  # pragma: no cover - assertion path
                        acquire_errors.append(exc)
                    finally:
                        acquire_done.set()

                worker = threading.Thread(target=acquire_while_reopening)
                inner_self._race_worker = worker
                worker.start()
                self.assertTrue(acquire_started.wait(timeout=1))
                inner_self._writer_finished_during_anchor_read = acquire_done.wait(
                    timeout=0.1
                )
                return anchor

        reopened = ReopeningStore(self.database, clock=self.clock)
        reopened._race_worker.join(timeout=2)
        self.assertFalse(reopened._race_worker.is_alive())
        self.assertFalse(reopened._writer_finished_during_anchor_read)
        self.assertEqual(acquire_errors, [])
        self.assertEqual(self.store.status()["generation"], 1)

    def test_concurrent_first_open_serializes_initialization(self) -> None:
        database = (
            Path(self.temporary.name)
            / "parallel-init"
            / "operator-fence.sqlite3"
        )
        barrier = threading.Barrier(12)
        errors: list[str] = []
        errors_lock = threading.Lock()

        def open_store() -> None:
            barrier.wait(timeout=5)
            try:
                store = fence.OperatorFenceStore(database)
                self.assertEqual(store.status()["generation"], 0)
            except BaseException as exc:  # pragma: no cover - assertion path
                with errors_lock:
                    errors.append(f"{type(exc).__name__}: {exc}")

        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [executor.submit(open_store) for _ in range(12)]
            for future in futures:
                future.result(timeout=5)

        self.assertEqual(errors, [])
        self.assertFalse(
            database.with_name(database.name + ".initializing").exists()
        )

    def test_interrupted_initialization_marker_recovers_cleanly(self) -> None:
        database = (
            Path(self.temporary.name)
            / "interrupted-init"
            / "operator-fence.sqlite3"
        )
        database.parent.mkdir(mode=0o700)
        database.write_bytes(b"")
        os.chmod(database, 0o600)
        session_key = database.with_name(database.name + ".session-key")
        session_key.write_bytes(b"x" * fence.SESSION_KEY_BYTES)
        os.chmod(session_key, 0o600)
        marker = database.with_name(database.name + ".initializing")
        marker.write_bytes(fence.INITIALIZATION_MARKER)
        os.chmod(marker, 0o600)

        store = fence.OperatorFenceStore(database)

        self.assertEqual(store.status()["generation"], 0)
        self.assertFalse(marker.exists())
        self.assertEqual(session_key.stat().st_size, fence.SESSION_KEY_BYTES)
        self.assertNotEqual(session_key.read_bytes(), b"x" * fence.SESSION_KEY_BYTES)

    def test_atomic_private_write_removes_tempfile_after_write_failure(self) -> None:
        target = self.database.parent / "atomic-write-test"
        with mock.patch.object(
            fence.os, "write", side_effect=OSError("simulated disk full")
        ):
            with self.assertRaisesRegex(OSError, "simulated disk full"):
                fence._atomic_private_write(target, b"payload")

        self.assertFalse(target.exists())
        self.assertEqual(
            list(target.parent.glob(f".{target.name}.*.tmp")),
            [],
        )

    def test_mutation_clock_is_sampled_after_writer_lock(self) -> None:
        clock_called = threading.Event()
        original_clock = self.store._clock

        def signaling_clock() -> int:
            clock_called.set()
            return original_clock()

        self.store._clock = signaling_clock
        raw = sqlite3.connect(self.database, isolation_level=None)
        raw.execute("BEGIN IMMEDIATE")
        result: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def acquire() -> None:
            try:
                result.append(
                    self.store.acquire(
                        owner_id="delayed-writer",
                        session_id="delayed-session",
                        reason="lock_wait",
                        lease_seconds=30,
                    )
                )
            except BaseException as exc:  # pragma: no cover - assertion path
                errors.append(exc)

        worker = threading.Thread(target=acquire)
        worker.start()
        try:
            self.assertFalse(clock_called.wait(timeout=0.1))
            self.clock.advance(10)
        finally:
            raw.execute("ROLLBACK")
            raw.close()
        worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result[0]["lease_until_unix"], 1_040)

    def test_quick_check_is_not_repeated_on_hot_connections(self) -> None:
        calls = 0
        real_validate_integrity = fence.OperatorFenceStore._validate_integrity

        def tracking_validate_integrity(connection: sqlite3.Connection) -> None:
            nonlocal calls
            calls += 1
            real_validate_integrity(connection)

        with mock.patch.object(
            fence.OperatorFenceStore,
            "_validate_integrity",
            new=staticmethod(tracking_validate_integrity),
        ):
            self.store.status()
            self.acquire_primary()
            self.store.status()
            self.assertEqual(calls, 0)
            reopened = fence.OperatorFenceStore(self.database, clock=self.clock)
            self.assertEqual(reopened.status()["generation"], 1)
            self.assertEqual(calls, 1)

    def test_connect_closes_connection_when_schema_validation_fails(self) -> None:
        raw = sqlite3.connect(self.database)
        try:
            raw.execute("CREATE TABLE unexpected(value TEXT)")
            raw.commit()
        finally:
            raw.close()

        real_connect = sqlite3.connect
        opened: list[sqlite3.Connection] = []

        class TrackingConnection(sqlite3.Connection):
            was_closed = False

            def close(self) -> None:
                self.was_closed = True
                super().close()

        def tracking_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
            kwargs["factory"] = TrackingConnection
            connection = real_connect(*args, **kwargs)
            opened.append(connection)
            return connection

        with mock.patch.object(fence.sqlite3, "connect", side_effect=tracking_connect):
            with self.assertRaisesRegex(fence.OperatorFenceError, "table set"):
                self.store.status()

        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0].was_closed)

    def test_event_schema_requires_observed_outcome(self) -> None:
        raw = sqlite3.connect(self.database)
        try:
            columns = {
                row[1]: row
                for row in raw.execute("PRAGMA table_info(effect_events)")
            }
        finally:
            raw.close()

        self.assertEqual(columns["observed_outcome"][3], 1)



if __name__ == "__main__":
    unittest.main()

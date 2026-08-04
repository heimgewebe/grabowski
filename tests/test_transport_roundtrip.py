from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_transport_roundtrip as roundtrip


BINDING = {
    "release_id": "release-1",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}
META_SCOPE = {"kind": "client_declared_meta", "label": "mcp-client-1"}
# The gate only ever admits an exactly intent-bound verification, so the shared
# helpers hand out a real intent. Tests that need an unbound handshake pass
# mutation_intent=None explicitly and assert that it authorizes nothing.
DEFAULT_INTENT = {
    "tool_name": "grabowski_file_write",
    "arguments_sha256": "e" * 64,
}
OTHER_SCOPE = {"kind": "client_declared_meta", "label": "mcp-client-2"}
SHARED_SCOPE = {
    "kind": "shared_unlabeled",
    "label": roundtrip.SHARED_UNLABELED_SCOPE,
}


def _consume_worker(
    state_root: str,
    start: multiprocessing.synchronize.Event,
    output: multiprocessing.queues.Queue,
) -> None:
    root = Path(state_root)
    roundtrip.STATE_ROOT = root
    roundtrip.LOCK_PATH = root / ".lock"
    start.wait()
    try:
        receipt = roundtrip.consume_verified(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name="grabowski_file_write",
            arguments_sha256="d" * 64,
            now_unix=102,
        )
    except Exception as exc:
        output.put(("error", type(exc).__name__))
    else:
        output.put(("ok", receipt["consumption_receipt_sha256"]))


def _consume_shared_worker(
    state_root: str,
    start: multiprocessing.synchronize.Event,
    output: multiprocessing.queues.Queue,
) -> None:
    root = Path(state_root)
    roundtrip.STATE_ROOT = root
    roundtrip.LOCK_PATH = root / ".lock"
    start.wait()
    try:
        receipt = roundtrip.consume_verified(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="grabowski_file_write",
            arguments_sha256="e" * 64,
            now_unix=102,
        )
    except Exception as exc:
        output.put(("error", type(exc).__name__))
    else:
        output.put(("ok", receipt["consumption_receipt_sha256"]))


class _TransportHarness(unittest.TestCase):
    """Shared state isolation and handshake helpers, no tests of its own."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name) / "state"
        self.state_root_patch = mock.patch.object(roundtrip, "STATE_ROOT", root)
        self.lock_path_patch = mock.patch.object(
            roundtrip, "LOCK_PATH", root / ".lock"
        )
        self.state_root_patch.start()
        self.lock_path_patch.start()
        self.addCleanup(self.state_root_patch.stop)
        self.addCleanup(self.lock_path_patch.stop)

    def begin(
        self,
        *,
        scope: dict[str, str] = META_SCOPE,
        now: int = 100,
        mutation_intent: dict[str, str] | None = DEFAULT_INTENT,
    ):
        return roundtrip.begin(
            client_scope=scope,
            runtime_binding=BINDING,
            mutation_intent=mutation_intent,
            now_unix=now,
        )

    def acknowledge(
        self,
        challenge: str,
        *,
        scope: dict[str, str] = META_SCOPE,
        now: int = 101,
    ):
        return roundtrip.acknowledge(
            client_scope=scope,
            challenge_receipt_sha256=challenge,
            runtime_binding=BINDING,
            now_unix=now,
        )

    def verify(
        self,
        *,
        scope: dict[str, str] = META_SCOPE,
        mutation_intent: dict[str, str] | None = DEFAULT_INTENT,
    ):
        begin = self.begin(scope=scope, mutation_intent=mutation_intent)
        return self.acknowledge(
            begin["challenge_receipt_sha256"], scope=scope
        )

    @staticmethod
    def intent(tool_name: str, digest_seed: str) -> dict[str, str]:
        """Build a distinct exact intent so pooled handshakes stay separable."""
        return {
            "tool_name": tool_name,
            "arguments_sha256": hashlib.sha256(
                digest_seed.encode("utf-8")
            ).hexdigest(),
        }


class TransportRoundtripTests(_TransportHarness):
    def test_begin_is_idempotent_until_ack_or_expiry(self) -> None:
        first = self.begin()
        second = self.begin(now=101)
        self.assertEqual(first["state"], "challenge_pending")
        self.assertFalse(first["mutation_gate_open"])
        self.assertFalse(first["replayed"])
        self.assertTrue(second["replayed"])
        self.assertEqual(
            first["challenge_receipt_sha256"],
            second["challenge_receipt_sha256"],
        )

    def test_ack_proves_response_possession_and_opens_single_use_gate(self) -> None:
        begin = self.begin()
        ack = self.acknowledge(begin["challenge_receipt_sha256"])
        self.assertEqual(ack["state"], "verified")
        self.assertTrue(ack["mutation_gate_open"])
        self.assertTrue(ack["single_use"])
        self.assertEqual(ack["client_scope_kind"], "client_declared_meta")
        # There is no generic "is the gate open" API any more: admission is
        # only ever proven by naming the exact target.
        self.assertFalse(hasattr(roundtrip, "require_verified"))
        consumed = roundtrip.consume_verified(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=102,
            **DEFAULT_INTENT,
        )
        self.assertEqual(consumed["state"], "consumed")

    def test_begin_reuses_fresh_verification(self) -> None:
        acknowledged = self.verify()
        replay = self.begin(now=102)
        self.assertEqual(replay["state"], "verified")
        self.assertTrue(replay["mutation_gate_open"])
        self.assertTrue(replay["replayed"])
        self.assertIsNone(replay["challenge_receipt_sha256"])
        self.assertEqual(
            replay["verification_receipt_sha256"],
            acknowledged["verification_receipt_sha256"],
        )

    def test_exact_ack_replay_is_idempotent_before_consumption(self) -> None:
        begin = self.begin()
        first = self.acknowledge(begin["challenge_receipt_sha256"])
        replay = self.acknowledge(
            begin["challenge_receipt_sha256"], now=102
        )
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(
            first["verification_receipt_sha256"],
            replay["verification_receipt_sha256"],
        )

    def test_consumption_binds_one_mutation_and_closes_gate(self) -> None:
        arguments_sha256 = roundtrip.canonical_arguments_sha256(
            {"path": "/tmp/example", "content": "x"}
        )
        verification = self.verify(
            mutation_intent={
                "tool_name": "grabowski_file_write",
                "arguments_sha256": arguments_sha256,
            }
        )
        consumed = roundtrip.consume_verified(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name="grabowski_file_write",
            arguments_sha256=arguments_sha256,
            now_unix=102,
        )
        self.assertEqual(consumed["state"], "consumed")
        self.assertEqual(
            consumed["verification_receipt_sha256"],
            verification["verification_receipt_sha256"],
        )
        self.assertEqual(consumed["arguments_sha256"], arguments_sha256)
        status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=103,
        )
        self.assertEqual(status["state"], "consumed")
        self.assertFalse(status["mutation_gate_open"])
        self.assertEqual(status["last_consumed_tool_name"], "grabowski_file_write")
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            roundtrip.consume_verified(
                client_scope=META_SCOPE,
                runtime_binding=BINDING,
                tool_name="grabowski_file_write",
                arguments_sha256=arguments_sha256,
                now_unix=104,
            )

    def test_concurrent_consumers_admit_exactly_one_mutation(self) -> None:
        self.verify(
            mutation_intent={
                "tool_name": "grabowski_file_write",
                "arguments_sha256": "d" * 64,
            }
        )
        context = multiprocessing.get_context("fork")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_consume_worker,
                args=(str(roundtrip.STATE_ROOT), start, output),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(timeout=10)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        results = sorted(output.get(timeout=2) for _ in processes)
        self.assertEqual(
            [result[0] for result in results],
            ["error", "ok"],
        )
        self.assertEqual(results[0][1], "TransportRoundtripRequired")

    def test_shared_unlabeled_handshakes_coexist_without_overwrite(self) -> None:
        first = self.begin(
            scope=SHARED_SCOPE,
            mutation_intent={"tool_name": "first-write", "arguments_sha256": "d" * 64},
        )
        second = self.begin(
            scope=SHARED_SCOPE,
            mutation_intent={"tool_name": "second-write", "arguments_sha256": "e" * 64},
        )
        self.assertFalse(first["replayed"])
        self.assertFalse(second["replayed"])
        self.assertNotEqual(
            first["challenge_receipt_sha256"],
            second["challenge_receipt_sha256"],
        )
        self.assertEqual(second["pending_challenge_count"], 2)

        second_ack = self.acknowledge(
            second["challenge_receipt_sha256"],
            scope=SHARED_SCOPE,
        )
        first_ack = self.acknowledge(
            first["challenge_receipt_sha256"],
            scope=SHARED_SCOPE,
        )
        self.assertNotEqual(
            first_ack["verification_receipt_sha256"],
            second_ack["verification_receipt_sha256"],
        )
        self.assertEqual(first_ack["verified_receipt_count"], 2)

        first_consumption = roundtrip.consume_verified(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="first-write",
            arguments_sha256="d" * 64,
            now_unix=102,
        )
        second_consumption = roundtrip.consume_verified(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="second-write",
            arguments_sha256="e" * 64,
            now_unix=102,
        )
        self.assertNotEqual(
            first_consumption["verification_receipt_sha256"],
            second_consumption["verification_receipt_sha256"],
        )
        self.assertEqual(second_consumption["verified_receipt_count"], 0)
        status = roundtrip.status(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            now_unix=103,
        )
        self.assertEqual(status["state"], "consumed")
        self.assertFalse(status["mutation_gate_open"])

    def test_shared_parallel_consumers_of_one_intent_admit_exactly_one(self) -> None:
        """Two callers racing for the same exact mutation admit one, not two.

        Under exact-intent binding an identical intent is the identical
        mutation, so `begin` collapses it to one handshake and single use
        admits it once. A second caller must fail closed rather than ride
        along on the first caller's verification.
        """
        begin = self.begin(scope=SHARED_SCOPE)
        self.acknowledge(
            begin["challenge_receipt_sha256"],
            scope=SHARED_SCOPE,
        )
        context = multiprocessing.get_context("fork")
        start = context.Event()
        output = context.Queue()
        processes = [
            context.Process(
                target=_consume_shared_worker,
                args=(str(roundtrip.STATE_ROOT), start, output),
            )
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        start.set()
        for process in processes:
            process.join(timeout=10)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, 0)
        results = sorted(output.get(timeout=2) for _ in processes)
        self.assertEqual([result[0] for result in results], ["error", "ok"])
        # The loser finds an empty pool once the winner consumed the single
        # verification, so it fails closed as "no verification at all".
        self.assertEqual(results[0][1], "TransportRoundtripRequired")

    def test_shared_intent_begin_replays_exact_pending_and_verified(self) -> None:
        arguments_sha256 = roundtrip.canonical_arguments_sha256({"sequence": 1})
        intent = {
            "tool_name": "write",
            "arguments_sha256": arguments_sha256,
        }
        first = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=100,
        )
        pending_replay = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=101,
        )
        self.assertTrue(pending_replay["replayed"])
        self.assertEqual(pending_replay["pending_challenge_count"], 1)
        self.assertEqual(
            pending_replay["challenge_receipt_sha256"],
            first["challenge_receipt_sha256"],
        )
        verified = self.acknowledge(
            first["challenge_receipt_sha256"],
            scope=SHARED_SCOPE,
            now=102,
        )
        verified_replay = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=103,
        )
        self.assertTrue(verified_replay["replayed"])
        self.assertEqual(verified_replay["verified_receipt_count"], 1)
        self.assertEqual(
            verified_replay["verification_receipt_sha256"],
            verified["verification_receipt_sha256"],
        )

    def test_intent_bound_shared_verifications_select_exact_mutation(self) -> None:
        first_arguments = roundtrip.canonical_arguments_sha256({"sequence": 1})
        second_arguments = roundtrip.canonical_arguments_sha256({"sequence": 2})
        first_begin = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "first-write",
                "arguments_sha256": first_arguments,
            },
            now_unix=100,
        )
        second_begin = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "second-write",
                "arguments_sha256": second_arguments,
            },
            now_unix=101,
        )
        first_ack = self.acknowledge(
            first_begin["challenge_receipt_sha256"],
            scope=SHARED_SCOPE,
            now=102,
        )
        second_ack = self.acknowledge(
            second_begin["challenge_receipt_sha256"],
            scope=SHARED_SCOPE,
            now=103,
        )
        self.assertTrue(first_ack["mutation_intent_bound"])
        self.assertEqual(first_ack["target_tool_name"], "first-write")
        self.assertEqual(second_ack["target_arguments_sha256"], second_arguments)
        with self.assertRaisesRegex(
            roundtrip.TransportMutationIntentMismatch,
            "no transport verification is bound to this exact mutation",
        ):
            roundtrip.consume_verified(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                tool_name="other-write",
                arguments_sha256="f" * 64,
                now_unix=104,
            )
        status = roundtrip.status(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            now_unix=104,
        )
        self.assertEqual(status["verified_receipt_count"], 2)
        second = roundtrip.consume_verified(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="second-write",
            arguments_sha256=second_arguments,
            now_unix=105,
        )
        first = roundtrip.consume_verified(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="first-write",
            arguments_sha256=first_arguments,
            now_unix=106,
        )
        self.assertTrue(second["verification_was_intent_bound"])
        self.assertTrue(first["verification_was_intent_bound"])
        self.assertEqual(
            second["verification_receipt_sha256"],
            second_ack["verification_receipt_sha256"],
        )
        self.assertEqual(
            first["verification_receipt_sha256"],
            first_ack["verification_receipt_sha256"],
        )

    def test_single_scope_replaces_pending_challenge_for_different_intent(self) -> None:
        first = self.begin()
        replacement = roundtrip.begin(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": "d" * 64,
            },
            now_unix=101,
        )
        self.assertFalse(replacement["replayed"])
        self.assertEqual(replacement["state"], "challenge_pending")
        self.assertNotEqual(replacement["challenge_receipt_sha256"], first["challenge_receipt_sha256"])
        self.assertEqual(replacement["pending_challenge_count"], 1)
        self.assertEqual(replacement["target_tool_name"], "write")
        with self.assertRaisesRegex(roundtrip.TransportRoundtripError, "missing"):
            self.acknowledge(first["challenge_receipt_sha256"], now=102)

    def test_single_scope_replaces_verified_receipt_for_different_intent(self) -> None:
        verified = self.verify()
        replacement = roundtrip.begin(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": "d" * 64,
            },
            now_unix=102,
        )
        self.assertFalse(replacement["replayed"])
        self.assertEqual(replacement["state"], "challenge_pending")
        self.assertEqual(replacement["verified_receipt_count"], 0)
        self.assertEqual(replacement["target_arguments_sha256"], "d" * 64)
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            roundtrip.consume_verified(
                client_scope=META_SCOPE,
                runtime_binding=BINDING,
                tool_name="other-write",
                arguments_sha256="e" * 64,
                now_unix=103,
            )
        self.assertNotEqual(replacement["challenge_receipt_sha256"], verified["verification_receipt_sha256"])

    def test_shared_pending_pool_is_bounded_and_prunes_stale_entries(self) -> None:
        with mock.patch.object(roundtrip, "MAX_SHARED_PENDING_CHALLENGES", 2):
            self.begin(
                scope=SHARED_SCOPE, now=100, mutation_intent=self.intent("w", "1")
            )
            self.begin(
                scope=SHARED_SCOPE, now=100, mutation_intent=self.intent("w", "2")
            )
            with self.assertRaisesRegex(
                roundtrip.TransportRoundtripRequired,
                "pending challenge pool is full",
            ):
                self.begin(
                    scope=SHARED_SCOPE, now=100, mutation_intent=self.intent("w", "3")
                )
            refreshed = self.begin(
                scope=SHARED_SCOPE,
                now=100 + roundtrip.CHALLENGE_TTL_SECONDS + 1,
                mutation_intent=self.intent("w", "4"),
            )
        self.assertEqual(refreshed["pending_challenge_count"], 1)

    def test_shared_verified_pool_is_bounded_and_preserves_pending_challenge(self) -> None:
        with mock.patch.object(roundtrip, "MAX_SHARED_VERIFIED_RECEIPTS", 1):
            first = self.begin(
                scope=SHARED_SCOPE, now=100, mutation_intent=self.intent("w", "1")
            )
            second = self.begin(
                scope=SHARED_SCOPE, now=100, mutation_intent=self.intent("w", "2")
            )
            self.acknowledge(
                first["challenge_receipt_sha256"],
                scope=SHARED_SCOPE,
                now=101,
            )
            with self.assertRaisesRegex(
                roundtrip.TransportRoundtripRequired,
                "verified receipt pool is full",
            ):
                self.acknowledge(
                    second["challenge_receipt_sha256"],
                    scope=SHARED_SCOPE,
                    now=101,
                )
            status = roundtrip.status(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                now_unix=102,
            )
        self.assertEqual(status["pending_challenge_count"], 1)
        self.assertEqual(status["verified_receipt_count"], 1)

    def test_legacy_single_slot_state_migrates_on_next_mutation(self) -> None:
        begin = self.begin()
        path = roundtrip._state_path(roundtrip.client_scope_sha256(META_SCOPE))
        current = json.loads(path.read_text(encoding="utf-8"))
        legacy = {
            "schema_version": roundtrip.SCHEMA_VERSION,
            "kind": roundtrip.STATE_KIND,
            "client_scope_sha256": current["client_scope_sha256"],
            "client_scope_kind": current["client_scope_kind"],
            "pending_challenge": current["pending_challenges"][0],
            "verified_receipt": None,
            "last_consumption_receipt": None,
        }
        roundtrip._write_private_json(path, legacy)
        acknowledged = self.acknowledge(begin["challenge_receipt_sha256"])
        migrated = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(migrated["schema_version"], roundtrip.STATE_SCHEMA_VERSION)
        self.assertEqual(len(migrated["verified_receipts"]), 1)
        self.assertEqual(acknowledged["state"], "verified")

    def test_different_client_scope_cannot_ack_or_consume(self) -> None:
        begin = self.begin()
        with self.assertRaisesRegex(roundtrip.TransportRoundtripError, "missing"):
            self.acknowledge(
                begin["challenge_receipt_sha256"], scope=OTHER_SCOPE
            )
        self.verify()
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            roundtrip.consume_verified(
                client_scope=OTHER_SCOPE,
                runtime_binding=BINDING,
                tool_name="write",
                arguments_sha256="d" * 64,
                now_unix=102,
            )

    def test_shared_unlabeled_scope_is_explicit_and_functional(self) -> None:
        begin = self.begin(scope=SHARED_SCOPE)
        ack = self.acknowledge(
            begin["challenge_receipt_sha256"], scope=SHARED_SCOPE
        )
        self.assertEqual(ack["client_scope_kind"], "shared_unlabeled")
        self.assertIn("authenticated client identity", ack["does_not_establish"])

    def test_expired_challenge_fails_closed(self) -> None:
        begin = self.begin()
        with self.assertRaisesRegex(roundtrip.TransportRoundtripError, "stale"):
            self.acknowledge(
                begin["challenge_receipt_sha256"],
                now=100 + roundtrip.CHALLENGE_TTL_SECONDS + 1,
            )

    def test_runtime_drift_closes_verified_gate(self) -> None:
        self.verify()
        drifted = {**BINDING, "repo_head": "d" * 40}
        status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=drifted,
            now_unix=102,
        )
        self.assertEqual(status["state"], "binding_mismatch")
        self.assertFalse(status["mutation_gate_open"])

    def test_status_without_state_is_side_effect_free(self) -> None:
        status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=100,
        )
        self.assertEqual(status["state"], "missing")
        self.assertFalse(status["mutation_gate_open"])
        self.assertFalse(roundtrip.STATE_ROOT.exists())

    def test_tampered_state_is_invalid_and_gate_remains_closed(self) -> None:
        self.begin()
        path = roundtrip._state_path(roundtrip.client_scope_sha256(META_SCOPE))
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["pending_challenges"][0]["runtime_binding"]["release_id"] = "tampered"
        path.write_text(json.dumps(payload), encoding="utf-8")
        os.chmod(path, 0o600)
        status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=101,
        )
        self.assertEqual(status["state"], "invalid")
        self.assertFalse(status["mutation_gate_open"])

    def test_private_modes_are_enforced(self) -> None:
        self.begin()
        path = roundtrip._state_path(roundtrip.client_scope_sha256(META_SCOPE))
        self.assertEqual(os.stat(roundtrip.STATE_ROOT).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(roundtrip.LOCK_PATH).st_mode & 0o777, 0o600)

    def test_symlinked_state_directory_fails_closed(self) -> None:
        target = Path(self.temporary.name) / "real-state"
        target.mkdir(mode=0o700)
        roundtrip.STATE_ROOT.symlink_to(target, target_is_directory=True)
        status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=100,
        )
        self.assertEqual(status["state"], "invalid")
        self.assertFalse(status["mutation_gate_open"])
        with self.assertRaises(roundtrip.TransportRoundtripError):
            self.begin()

    def test_symlinked_lock_file_fails_closed(self) -> None:
        roundtrip.STATE_ROOT.mkdir(mode=0o700)
        target = Path(self.temporary.name) / "lock-target"
        target.write_bytes(b"")
        os.chmod(target, 0o600)
        roundtrip.LOCK_PATH.symlink_to(target)
        with self.assertRaises(OSError):
            self.begin()

    def test_symlinked_or_hardlinked_state_file_is_invalid(self) -> None:
        roundtrip.STATE_ROOT.mkdir(mode=0o700)
        path = roundtrip._state_path(roundtrip.client_scope_sha256(META_SCOPE))
        target = Path(self.temporary.name) / "state-target"
        target.write_text("{}", encoding="utf-8")
        os.chmod(target, 0o600)
        path.symlink_to(target)
        symlink_status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=100,
        )
        self.assertEqual(symlink_status["state"], "invalid")
        path.unlink()
        self.begin()
        sibling = path.with_suffix(".hardlink")
        os.link(path, sibling)
        hardlink_status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=101,
        )
        self.assertEqual(hardlink_status["state"], "invalid")
        self.assertFalse(hardlink_status["mutation_gate_open"])

    def test_unsafe_state_permissions_are_invalid(self) -> None:
        self.begin()
        path = roundtrip._state_path(roundtrip.client_scope_sha256(META_SCOPE))
        os.chmod(path, 0o640)
        status = roundtrip.status(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=101,
        )
        self.assertEqual(status["state"], "invalid")
        self.assertFalse(status["mutation_gate_open"])

    def test_noncanonical_arguments_fail_before_consumption(self) -> None:
        self.verify()
        with self.assertRaisesRegex(
            roundtrip.TransportRoundtripError, "canonical JSON"
        ):
            roundtrip.canonical_arguments_sha256({"bad": object()})
        self.assertTrue(
            roundtrip.status(
                client_scope=META_SCOPE,
                runtime_binding=BINDING,
                now_unix=102,
            )["mutation_gate_open"]
        )


class UnboundVerificationAuthorizesNothingTests(_TransportHarness):
    """T139: an unbound handshake must never exist, let alone admit anything."""

    def test_unbound_begin_is_refused_fail_closed(self) -> None:
        with self.assertRaises(roundtrip.TransportMutationIntentRequired) as caught:
            self.begin(mutation_intent=None)
        self.assertIn("requires an exact mutation intent", str(caught.exception))

    def test_unbound_begin_cannot_occupy_the_bounded_pool(self) -> None:
        """Pool DoS: unbound handshakes must not crowd out exact ones."""
        with mock.patch.object(roundtrip, "MAX_SHARED_PENDING_CHALLENGES", 2):
            for _ in range(5):
                with self.assertRaises(roundtrip.TransportMutationIntentRequired):
                    self.begin(scope=SHARED_SCOPE, mutation_intent=None)
            # The pool is untouched, so exact handshakes still fit.
            first = self.begin(
                scope=SHARED_SCOPE, mutation_intent=self.intent("w", "1")
            )
            second = self.begin(
                scope=SHARED_SCOPE, mutation_intent=self.intent("w", "2")
            )
        self.assertEqual(first["pending_challenge_count"], 1)
        self.assertEqual(second["pending_challenge_count"], 2)

    def test_legacy_unbound_entries_are_discarded_on_sight_not_at_ttl(self) -> None:
        """Pre-existing unbound state must never occupy the pool or authorize."""
        self.begin(scope=SHARED_SCOPE, mutation_intent=self.intent("w", "keep"))
        path = roundtrip._state_path(roundtrip._sha256_json(SHARED_SCOPE))
        state = json.loads(path.read_text(encoding="utf-8"))
        legacy = dict(state["pending_challenges"][0])
        for key in ("tool_name", "arguments_sha256"):
            legacy.pop(key, None)
        legacy["challenge_nonce_sha256"] = "a" * 64
        legacy["receipt_sha256"] = roundtrip._receipt_sha256(legacy)
        state["pending_challenges"] = [*state["pending_challenges"], legacy]
        path.write_text(json.dumps(state), encoding="utf-8")
        os.chmod(path, 0o600)

        projected = roundtrip.status(
            client_scope=SHARED_SCOPE, runtime_binding=BINDING, now_unix=101
        )
        # The unbound entry is invisible immediately, well inside its TTL.
        self.assertEqual(projected["pending_challenge_count"], 1)
        with self.assertRaises(roundtrip.TransportMutationIntentRequired):
            self.acknowledge(
                legacy["receipt_sha256"], scope=SHARED_SCOPE, now=101
            )

    def test_legacy_unbound_verified_replay_is_refused(self) -> None:
        """The ack replay path reads unpruned state and must still fail closed."""
        begun = self.begin(scope=SHARED_SCOPE, mutation_intent=self.intent("w", "x"))
        self.acknowledge(begun["challenge_receipt_sha256"], scope=SHARED_SCOPE)
        path = roundtrip._state_path(roundtrip._sha256_json(SHARED_SCOPE))
        state = json.loads(path.read_text(encoding="utf-8"))
        legacy = dict(state["verified_receipts"][0])
        for key in ("tool_name", "arguments_sha256"):
            legacy.pop(key, None)
        legacy["receipt_sha256"] = roundtrip._receipt_sha256(legacy)
        state["verified_receipts"] = [legacy]
        path.write_text(json.dumps(state), encoding="utf-8")
        os.chmod(path, 0o600)

        with self.assertRaises(roundtrip.TransportMutationIntentRequired):
            self.acknowledge(
                str(legacy["challenge_receipt_sha256"]),
                scope=SHARED_SCOPE,
                now=102,
            )
        # It is also invisible to the projection rather than merely unusable.
        projected = roundtrip.status(
            client_scope=SHARED_SCOPE, runtime_binding=BINDING, now_unix=102
        )
        self.assertEqual(projected["verified_receipt_count"], 0)
        self.assertFalse(projected["mutation_gate_open"])

    def test_error_names_the_caller_scope_and_the_exact_requested_target(self) -> None:
        self.verify(mutation_intent=self.intent("intended-write", "1"))
        with self.assertRaises(roundtrip.TransportMutationIntentMismatch) as caught:
            roundtrip.consume_verified(
                client_scope=META_SCOPE,
                runtime_binding=BINDING,
                tool_name="foreign-write",
                arguments_sha256="f" * 64,
                now_unix=102,
            )
        message = str(caught.exception)
        self.assertIn("client_scope_sha256=", message)
        self.assertIn("tool_name=foreign-write", message)
        self.assertIn("arguments_sha256=" + "f" * 64, message)
        self.assertIn("intent_bound_verifications=1", message)

    def test_verification_for_one_target_does_not_admit_another(self) -> None:
        self.verify(mutation_intent=self.intent("write-a", "a"))
        with self.assertRaises(roundtrip.TransportMutationIntentMismatch):
            roundtrip.consume_verified(
                client_scope=META_SCOPE,
                runtime_binding=BINDING,
                now_unix=102,
                **self.intent("write-b", "b"),
            )
        # The rejected attempt must not have consumed the intended verification.
        admitted = roundtrip.consume_verified(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=102,
            **self.intent("write-a", "a"),
        )
        self.assertEqual(admitted["state"], "consumed")
        self.assertTrue(admitted["verification_was_intent_bound"])

    def test_same_arguments_under_a_different_tool_are_refused(self) -> None:
        digest = roundtrip.canonical_arguments_sha256({"path": "/tmp/x"})
        self.verify(
            mutation_intent={"tool_name": "write", "arguments_sha256": digest}
        )
        with self.assertRaises(roundtrip.TransportMutationIntentMismatch):
            roundtrip.consume_verified(
                client_scope=META_SCOPE,
                runtime_binding=BINDING,
                tool_name="delete",
                arguments_sha256=digest,
                now_unix=102,
            )


if __name__ == "__main__":
    unittest.main()

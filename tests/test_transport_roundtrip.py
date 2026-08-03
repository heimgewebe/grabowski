from __future__ import annotations

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


class TransportRoundtripTests(unittest.TestCase):
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

    def begin(self, *, scope: dict[str, str] = META_SCOPE, now: int = 100):
        return roundtrip.begin(
            client_scope=scope,
            runtime_binding=BINDING,
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

    def verify(self, *, scope: dict[str, str] = META_SCOPE):
        begin = self.begin(scope=scope)
        return self.acknowledge(
            begin["challenge_receipt_sha256"], scope=scope
        )

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
        status = roundtrip.require_verified(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            now_unix=102,
        )
        self.assertTrue(status["mutation_gate_open"])

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
        verification = self.verify()
        arguments_sha256 = roundtrip.canonical_arguments_sha256(
            {"path": "/tmp/example", "content": "x"}
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
        self.verify()
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
        payload["pending_challenge"]["runtime_binding"]["release_id"] = "tampered"
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


if __name__ == "__main__":
    unittest.main()

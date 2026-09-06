from __future__ import annotations

from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_effect_interceptor as interceptor
import grabowski_operator_fence as fence
import grabowski_operator_fence_enforcement as enforcement
import grabowski_operator_fence_rpc as rpc
import grabowski_operator_fence_shadow as fence_shadow


class Clock:
    def __init__(self, value: int = 1_000) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += seconds


class DropBeforeApplyClient:
    def __init__(
        self,
        store: fence.OperatorFenceStore,
        peer_id: str,
        operation: str,
        shared: dict[str, bool],
    ) -> None:
        self.store = store
        self.peer_id = peer_id
        self.operation = operation
        self.shared = shared
        self.requests: list[dict[str, object]] = []

    def call(self, request):
        self.requests.append(dict(request))
        if (
            request.get("operation") == self.operation
            and self.shared.get("dropped") is not True
        ):
            self.shared["dropped"] = True
            raise RuntimeError(f"lost-before {self.operation}")
        return rpc.dispatch_request(self.store, peer_id=self.peer_id, request=request)


class DropAfterApplyClient:
    def __init__(
        self,
        store: fence.OperatorFenceStore,
        peer_id: str,
        operation: str,
        shared: dict[str, bool],
    ) -> None:
        self.store = store
        self.peer_id = peer_id
        self.operation = operation
        self.shared = shared
        self.requests: list[dict[str, object]] = []

    def call(self, request):
        self.requests.append(dict(request))
        response = rpc.dispatch_request(
            self.store, peer_id=self.peer_id, request=request
        )
        if (
            request.get("operation") == self.operation
            and self.shared.get("dropped") is not True
        ):
            self.shared["dropped"] = True
            raise RuntimeError(f"lost {self.operation} response")
        return response


class FakeClient:
    def __init__(self, store: fence.OperatorFenceStore, peer_id: str) -> None:
        self.store = store
        self.peer_id = peer_id
        self.requests: list[dict[str, object]] = []

    def call(self, request):
        self.requests.append(dict(request))
        return rpc.dispatch_request(self.store, peer_id=self.peer_id, request=request)


class OperatorFenceEnforcementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.clock = Clock()
        self.store = fence.OperatorFenceStore(
            self.root / "fence" / "operator-fence.sqlite3", clock=self.clock
        )
        self.config_path = self.root / "client" / "enforcement.json"
        self.state_path = self.root / "client" / "state.json"
        self.config_path.parent.mkdir(mode=0o700)
        self.clients: list[FakeClient] = []
        self.write_config("grabowski")
        self.addCleanup(self.release_local_lock)

    def release_local_lock(self) -> None:
        if enforcement._FENCE_ENFORCEMENT_LOCK.locked():
            enforcement._FENCE_ENFORCEMENT_LOCK.release()

    def write_config(self, peer_id: str, *, minimum_generation_seen: int = 0) -> None:
        document = {
            "schema_version": 1,
            "kind": enforcement.FENCE_ENFORCEMENT_CONFIG_KIND,
            "mode": "enforce",
            "host": "heimberry",
            "remote_user": "operator-fence",
            "peer_id": peer_id,
            "known_hosts_path": str(self.root / "known_hosts"),
            "identity_file": str(self.root / "identity"),
            "host_key_alias": "heimberry",
            "expected_instance_id": self.store.status()["instance_id"],
            "minimum_generation_seen": minimum_generation_seen,
            "lease_seconds": 30,
        }
        self.config_path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.config_path, 0o600)

    def client_factory(self, **kwargs):
        client = FakeClient(self.store, kwargs["expected_peer_id"])
        self.clients.append(client)
        return client

    @staticmethod
    def admission(tool: str = "grabowski_resource_acquire") -> dict[str, object]:
        return interceptor.receipts.admit(
            tool=tool,
            arguments={"resource_keys": ["path:/tmp/g65-sentinel"]},
            runtime_sha256="a" * 64,
            transport_receipt_sha256="b" * 64,
            effect_class="mutating",
            lane_id="lane-test",
            actor_id="controller:test",
            resource_keys=["path:/tmp/g65-sentinel"],
            append_audit=None,
        )

    def begin(self, admission=None):
        return enforcement.begin_fence_enforcement(
            admission or self.admission(),
            config_path=self.config_path,
            state_path=self.state_path,
            client_factory=self.client_factory,
        )

    def simulate_process_death(self, token) -> None:
        # In production the kernel releases both the process-local file lock and
        # all in-process state when the process exits. Exercise the same durable
        # state recovery from this surviving test process.
        enforcement._fence_release_locks(token)

    def test_config_absent_disables_without_state_or_rpc(self) -> None:
        missing = self.root / "missing.json"
        token = enforcement.begin_fence_enforcement(
            self.admission(),
            config_path=missing,
            state_path=self.state_path,
            client_factory=self.client_factory,
        )
        self.assertIsNone(token)
        self.assertFalse(self.state_path.exists())
        self.assertEqual(self.clients, [])

    def test_config_absent_does_not_validate_admission(self) -> None:
        token = enforcement.begin_fence_enforcement(
            {"malformed": True},
            config_path=self.root / "missing.json",
            state_path=self.state_path,
            client_factory=self.client_factory,
        )
        self.assertIsNone(token)
        self.assertFalse(self.state_path.exists())
        self.assertEqual(self.clients, [])

    def test_required_rejects_unsafe_config_permissions(self) -> None:
        os.chmod(self.config_path, 0o644)
        with self.assertRaisesRegex(
            enforcement.OperatorFenceEnforcementError, "unsafe_fence_file"
        ):
            enforcement.fence_enforcement_required(self.config_path)

    def test_required_rejects_extra_config_keys(self) -> None:
        document = json.loads(self.config_path.read_text(encoding="utf-8"))
        document["unexpected"] = True
        self.config_path.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(self.config_path, 0o600)
        with self.assertRaisesRegex(
            enforcement.OperatorFenceEnforcementError,
            "invalid_fence_config_shape",
        ):
            enforcement.fence_enforcement_required(self.config_path)

    def test_process_lock_serializes_distinct_file_descriptors(self) -> None:
        first = enforcement._fence_acquire_process_lock(
            self.state_path, timeout_seconds=0.1
        )
        try:
            lock_path = enforcement._fence_process_lock_path(self.state_path)
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(
                enforcement.OperatorFenceEnforcementDenied, "local_effect_inflight"
            ):
                enforcement._fence_acquire_process_lock(
                    self.state_path, timeout_seconds=0.05
                )
        finally:
            os.close(first)

    def test_successful_effect_acquires_begins_settles_and_releases(self) -> None:
        admission = self.admission()
        token = self.begin(admission)
        self.assertIsNotNone(token)
        begun = self.store.status()
        self.assertEqual(begun["generation"], 1)
        self.assertEqual(begun["writer"]["owner_id"], "grabowski")
        self.assertEqual(begun["inflight"]["operation_id"], admission["request_id"])

        enforcement.mark_fence_dispatching(token)
        completion = interceptor.build_success_completion(admission, {"ok": True})
        result = enforcement.finish_fence_success(
            token, evidence_sha256=completion["completion_sha256"]
        )
        self.assertEqual(result, {"terminal": True, "outcome": "effect_applied"})
        status = self.store.status()
        self.assertIsNone(status["writer"])
        self.assertIsNone(status["inflight"])
        self.assertEqual(status["last_settlement"]["outcome"], "effect_applied")
        self.assertEqual(
            status["last_settlement"]["evidence_sha256"], completion["completion_sha256"]
        )
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["minimum_generation_seen"], 1)
        self.assertIsNone(state["pending"])
        self.assertEqual(self.state_path.stat().st_mode & 0o777, 0o600)

    def test_live_other_writer_denies_before_domain_dispatch(self) -> None:
        secondary = self.store.acquire(
            owner_id="der-kleine-maulwurf",
            session_id="secondary-session",
            reason="g6.5_effect",
            lease_seconds=30,
        )
        with self.assertRaisesRegex(
            enforcement.OperatorFenceEnforcementDenied, "writer_active"
        ):
            self.begin()
        self.assertEqual(self.store.status()["generation"], secondary["generation"])
        self.assertIsNone(self.store.status()["inflight"])

    def test_restart_before_dispatch_is_settled_not_applied_then_new_effect_starts(self) -> None:
        first = self.admission("grabowski_git")
        token = self.begin(first)
        self.simulate_process_death(token)
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["pending"]["phase"], "begun")

        second = self.admission("grabowski_resource_acquire")
        token2 = self.begin(second)
        status = self.store.status()
        self.assertEqual(status["generation"], 2)
        self.assertEqual(status["inflight"]["operation_id"], second["request_id"])
        settlements = self.store._connect().execute(
            "SELECT operation_id,outcome FROM settlements ORDER BY settlement_id"
        ).fetchall()
        self.assertEqual(
            [(row["operation_id"], row["outcome"]) for row in settlements],
            [(first["request_id"], "effect_not_applied")],
        )
        enforcement.abort_fence_before_dispatch(token2)

    def test_restart_after_dispatch_becomes_outcome_unknown_and_blocks(self) -> None:
        first = self.admission("grabowski_git")
        token = self.begin(first)
        enforcement.mark_fence_dispatching(token)
        self.simulate_process_death(token)

        with self.assertRaisesRegex(
            enforcement.OperatorFenceEnforcementDenied, "outcome_unknown"
        ):
            self.begin(self.admission("grabowski_resource_acquire"))
        status = self.store.status()
        self.assertEqual(status["inflight"]["operation_id"], first["request_id"])
        self.assertEqual(status["inflight"]["state"], "outcome_unknown")
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["pending"]["phase"], "outcome_unknown")

        with self.assertRaisesRegex(
            enforcement.OperatorFenceEnforcementDenied, "unresolved_inflight"
        ):
            self.begin(self.admission("grabowski_resource_release"))

    def test_typed_reconcile_clears_exact_outcome_unknown_and_allows_next_generation(self) -> None:
        first = self.admission("grabowski_git")
        token = self.begin(first)
        enforcement.mark_fence_dispatching(token)
        self.simulate_process_death(token)

        with self.assertRaisesRegex(
            enforcement.OperatorFenceEnforcementDenied, "outcome_unknown"
        ):
            self.begin(self.admission("grabowski_resource_acquire"))
        pending_state, _ = enforcement._fence_read_json(self.state_path)
        pending = pending_state["pending"]
        self.assertEqual(pending["phase"], "outcome_unknown")
        self.clock.advance(31)
        reconciliation = self.store.reconcile_effect(
            reconciler_id="typed-target-readback",
            generation=pending["generation"],
            operation_id=pending["operation_id"],
            operation_name=pending["operation_name"],
            intent_sha256=pending["intent_sha256"],
            outcome="effect_applied",
            evidence_sha256="e" * 64,
            expected_instance_id=self.store.status()["instance_id"],
            minimum_generation_seen=pending["generation"],
        )
        settlement = reconciliation["recorded_settlement"]
        self.assertEqual(settlement["resolution_source"], "reconcile")
        self.assertEqual(settlement["outcome"], "effect_applied")

        second = self.admission("grabowski_resource_acquire")
        token2 = self.begin(second)
        status = self.store.status()
        self.assertEqual(status["generation"], 2)
        self.assertEqual(status["inflight"]["operation_id"], second["request_id"] )
        state2, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state2["pending"]["operation_id"], second["request_id"] )
        enforcement.abort_fence_before_dispatch(token2)

    def test_exception_completion_marks_remote_outcome_unknown(self) -> None:
        admission = self.admission("grabowski_git")
        token = self.begin(admission)
        enforcement.mark_fence_dispatching(token)
        completion = interceptor.build_exception_completion(
            admission, RuntimeError("response lost")
        )
        result = enforcement.finish_fence_unknown(
            token, evidence_sha256=completion["completion_sha256"]
        )
        self.assertEqual(result, {"terminal": False, "outcome": "outcome_unknown"})
        status = self.store.status()
        self.assertEqual(status["inflight"]["state"], "outcome_unknown")
        self.assertEqual(
            status["last_event"]["evidence_sha256"], completion["completion_sha256"]
        )

    def drop_factory(self, operation: str):
        shared = {"dropped": False}

        def factory(**kwargs):
            client = DropAfterApplyClient(
                self.store, kwargs["expected_peer_id"], operation, shared
            )
            self.clients.append(client)
            return client

        return factory, shared

    def test_acquire_response_loss_replays_same_generation_then_recovers(self) -> None:
        first = self.admission("grabowski_git")
        factory, shared = self.drop_factory("acquire")
        with self.assertRaisesRegex(RuntimeError, "lost acquire response"):
            enforcement.begin_fence_enforcement(
                first,
                config_path=self.config_path,
                state_path=self.state_path,
                client_factory=factory,
            )
        self.assertTrue(shared["dropped"])
        status = self.store.status()
        self.assertEqual(status["generation"], 1)
        self.assertEqual(status["writer"]["owner_id"], "grabowski")
        self.assertIsNone(status["inflight"])
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["pending"]["phase"], "prepared")

        token = enforcement.begin_fence_enforcement(
            self.admission("grabowski_resource_acquire"),
            config_path=self.config_path,
            state_path=self.state_path,
            client_factory=self.client_factory,
        )
        self.assertEqual(self.store.status()["generation"], 2)
        settlements = self.store._connect().execute(
            "SELECT operation_id,outcome FROM settlements ORDER BY settlement_id"
        ).fetchall()
        self.assertEqual(
            [(row["operation_id"], row["outcome"]) for row in settlements],
            [(first["request_id"], "effect_not_applied")],
        )
        enforcement.abort_fence_before_dispatch(token)

    def test_expired_grant_before_begin_is_released_without_false_effect(self) -> None:
        first = self.admission("grabowski_git")
        shared = {"dropped": False}

        def factory(**kwargs):
            client = DropBeforeApplyClient(
                self.store, kwargs["expected_peer_id"], "begin", shared
            )
            self.clients.append(client)
            return client

        with self.assertRaisesRegex(RuntimeError, "lost-before begin"):
            enforcement.begin_fence_enforcement(
                first,
                config_path=self.config_path,
                state_path=self.state_path,
                client_factory=factory,
            )
        self.assertTrue(shared["dropped"])
        status = self.store.status()
        self.assertEqual(status["generation"], 1)
        self.assertIsNone(status["inflight"])
        self.assertEqual(status["writer"]["owner_id"], "grabowski")
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["pending"]["phase"], "granted")

        self.clock.advance(31)
        second = self.admission("grabowski_resource_acquire")
        token = self.begin(second)
        status = self.store.status()
        self.assertEqual(status["generation"], 2)
        self.assertEqual(status["inflight"]["operation_id"], second["request_id"])
        settlements = self.store._connect().execute(
            "SELECT operation_id,outcome FROM settlements ORDER BY settlement_id"
        ).fetchall()
        self.assertEqual(settlements, [])
        enforcement.abort_fence_before_dispatch(token)

    def test_begin_response_loss_recovers_as_not_applied(self) -> None:
        first = self.admission("grabowski_git")
        factory, shared = self.drop_factory("begin")
        with self.assertRaisesRegex(RuntimeError, "lost begin response"):
            enforcement.begin_fence_enforcement(
                first,
                config_path=self.config_path,
                state_path=self.state_path,
                client_factory=factory,
            )
        self.assertTrue(shared["dropped"])
        status = self.store.status()
        self.assertEqual(status["inflight"]["operation_id"], first["request_id"])
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["pending"]["phase"], "granted")

        token = self.begin(self.admission("grabowski_resource_acquire"))
        settlements = self.store._connect().execute(
            "SELECT operation_id,outcome FROM settlements ORDER BY settlement_id"
        ).fetchall()
        self.assertEqual(
            [(row["operation_id"], row["outcome"]) for row in settlements],
            [(first["request_id"], "effect_not_applied")],
        )
        enforcement.abort_fence_before_dispatch(token)

    def test_settle_response_loss_is_replayed_from_completion_ready(self) -> None:
        admission = self.admission("grabowski_git")
        token = self.begin(admission)
        enforcement.mark_fence_dispatching(token)
        completion = interceptor.build_success_completion(admission, {"ok": True})
        factory, shared = self.drop_factory("settle")
        token["client"] = factory(expected_peer_id="grabowski")
        with self.assertRaisesRegex(RuntimeError, "lost settle response"):
            enforcement.finish_fence_success(
                token, evidence_sha256=completion["completion_sha256"]
            )
        self.assertTrue(shared["dropped"])
        self.assertIsNone(self.store.status()["inflight"])
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state["pending"]["phase"], "completion_ready")

        token2 = self.begin(self.admission("grabowski_resource_acquire"))
        self.assertEqual(self.store.status()["generation"], 2)
        state2, _ = enforcement._fence_read_json(self.state_path)
        self.assertEqual(state2["pending"]["operation_id"], token2["operation_id"])
        enforcement.abort_fence_before_dispatch(token2)

    def test_release_response_loss_is_reconciled_by_status(self) -> None:
        admission = self.admission("grabowski_git")
        token = self.begin(admission)
        enforcement.mark_fence_dispatching(token)
        completion = interceptor.build_success_completion(admission, {"ok": True})
        factory, shared = self.drop_factory("release")
        token["client"] = factory(expected_peer_id="grabowski")
        result = enforcement.finish_fence_success(
            token, evidence_sha256=completion["completion_sha256"]
        )
        self.assertTrue(shared["dropped"])
        self.assertEqual(result, {"terminal": True, "outcome": "effect_applied"})
        status = self.store.status()
        self.assertIsNone(status["writer"])
        self.assertIsNone(status["inflight"])
        state, _ = enforcement._fence_read_json(self.state_path)
        self.assertIsNone(state["pending"])

    def test_core_admission_audit_failure_preserves_fence_identity(self) -> None:
        disabled = {
            "status": "disabled",
            "decision": "not_observed",
            "observation_sha256": "9" * 64,
        }
        with mock.patch.object(fence_shadow, "observe", return_value=disabled):
            admission = interceptor.admit_mutation(
                tool_name="grabowski_git",
                arguments={"repo": "/tmp/repo"},
                transport_evidence={
                    "runtime_binding_sha256": "a" * 64,
                    "consumption_receipt_sha256": "b" * 64,
                },
                append_audit=lambda _record: (_ for _ in ()).throw(
                    RuntimeError("audit unavailable")
                ),
            )
        validated = interceptor.receipts.validate_admission(admission)
        self.assertRegex(validated["admission_sha256"], r"^[0-9a-f]{64}$")
        self.assertIsNone(admission["audit_record_sha256"])


if __name__ == "__main__":
    unittest.main()

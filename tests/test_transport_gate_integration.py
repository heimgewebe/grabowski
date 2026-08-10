from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import grabowski_grips as grips
from tests.test_operator_v2_runtime import _load_grabowski_mcp
import grabowski_transport_roundtrip as roundtrip
import grabowski_serving_process as serving
from tests.test_operator_contract import _load_operator_module


BINDING = {
    "release_id": "release-1",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}
META_SCOPE = {"kind": "client_declared_meta", "label": "mcp-client-1"}
SHARED_SCOPE = {
    "kind": "shared_unlabeled",
    "label": roundtrip.SHARED_UNLABELED_SCOPE,
}


class TransportGripIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        self.root_patch = mock.patch.object(roundtrip, "STATE_ROOT", root)
        self.lock_patch = mock.patch.object(roundtrip, "LOCK_PATH", root / ".lock")
        self.root_patch.start()
        self.lock_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.lock_patch.stop)

    @staticmethod
    def parameters(action: str, **extra: object) -> dict[str, object]:
        parameters = {
            "action": action,
            "_server_transport_client_scope": META_SCOPE,
            "_server_transport_runtime_binding": BINDING,
            **extra,
        }
        # Only an exactly bound handshake can open the gate, so begin carries a
        # target unless a test deliberately exercises the unbound path.
        if action == "begin" and "target_tool_name" not in extra:
            parameters["target_tool_name"] = "write"
            parameters["target_arguments"] = {}
        return parameters

    def test_begin_and_ack_are_receipt_bound_through_existing_grip_surface(self) -> None:
        begin = grips.grip_run(
            "transport-roundtrip",
            self.parameters("begin"),
            profile="operator",
            allow_mutation=True,
        )
        self.assertEqual(begin["status"], "passed")
        self.assertEqual(begin["output"]["state"], "challenge_pending")
        challenge = begin["output"]["challenge_receipt_sha256"]
        ack = grips.grip_run(
            "transport-roundtrip",
            self.parameters("ack", challenge_receipt_sha256=challenge),
            profile="operator",
            allow_mutation=True,
        )
        self.assertEqual(ack["status"], "passed")
        self.assertEqual(ack["output"]["state"], "verified")
        self.assertTrue(ack["output"]["mutation_gate_open"])
        self.assertEqual(ack["output"]["client_scope_kind"], "client_declared_meta")
        self.assertEqual(
            [item["status"] for item in ack["receipt"]["checks"][-4:]],
            ["pass", "pass", "pass", "pass"],
        )

    def test_grip_binds_exact_target_mutation(self) -> None:
        arguments = {"path": "/tmp/example", "content": "x"}
        begin = grips.grip_run(
            "transport-roundtrip",
            self.parameters(
                "begin",
                target_tool_name="write",
                target_arguments=arguments,
            ),
            profile="operator",
            allow_mutation=True,
        )
        self.assertEqual(begin["status"], "passed")
        self.assertTrue(begin["output"]["mutation_intent_bound"])
        self.assertEqual(begin["output"]["target_tool_name"], "write")
        self.assertEqual(
            begin["output"]["target_arguments_sha256"],
            roundtrip.canonical_arguments_sha256(arguments),
        )
        ack = grips.grip_run(
            "transport-roundtrip",
            self.parameters(
                "ack",
                challenge_receipt_sha256=begin["output"]["challenge_receipt_sha256"],
            ),
            profile="operator",
            allow_mutation=True,
        )
        self.assertTrue(ack["output"]["mutation_intent_bound"])
        self.assertEqual(ack["output"]["target_tool_name"], "write")

    def test_published_contract_states_the_conditional_target_binding(self) -> None:
        contract = next(
            item
            for item in grips.list_grips(profile="operator")
            if item["name"] == "transport-roundtrip"
        )
        self.assertEqual(contract["version"], "2.1")
        self.assertIn("exact-target-bound", contract["acceptance_ids"])
        combined = contract["summary"] + contract["recovery_path"]
        for fragment in ("server-retained", "compatibility", "action=execute"):
            self.assertIn(fragment, combined)
        preconditions = " | ".join(contract["preconditions"])
        self.assertIn(
            "action=begin requires target_tool_name and target_arguments together",
            preconditions,
        )
        self.assertIn("action=execute requires challenge_receipt_sha256", preconditions)
        self.assertIn("MCP wrapper may inject", preconditions)
        self.assertIn("shared_unlabeled callers are refused", preconditions)
        self.assertEqual(contract["required_parameters"], ["action"])

    def test_unbound_begin_is_refused_by_the_grip_preflight(self) -> None:
        blocked = grips.grip_run(
            "transport-roundtrip",
            {
                "action": "begin",
                "_server_transport_client_scope": META_SCOPE,
                "_server_transport_runtime_binding": BINDING,
            },
            profile="operator",
            allow_mutation=True,
        )
        self.assertEqual(blocked["status"], "blocked")
        self.assertIn("requires target_tool_name", blocked["output"]["error"])

    def test_bound_begin_emits_the_exact_target_check(self) -> None:
        begun = grips.grip_run(
            "transport-roundtrip",
            self.parameters("begin"),
            profile="operator",
            allow_mutation=True,
        )
        checks = {item["id"]: item for item in begun["receipt"]["checks"]}
        self.assertEqual(checks["exact-target-bound"]["status"], "pass")
        self.assertIn("write:", checks["exact-target-bound"]["detail"])

    def test_ack_is_not_forced_to_carry_begin_fields(self) -> None:
        begun = grips.grip_run(
            "transport-roundtrip",
            self.parameters("begin"),
            profile="operator",
            allow_mutation=True,
        )
        acked = grips.grip_run(
            "transport-roundtrip",
            self.parameters(
                "ack",
                challenge_receipt_sha256=begun["output"]["challenge_receipt_sha256"],
            ),
            profile="operator",
            allow_mutation=True,
        )
        self.assertEqual(acked["status"], "passed")
        self.assertEqual(acked["output"]["state"], "verified")

    def test_execute_dispatches_exact_target_with_private_capability(self) -> None:
        arguments = {"path": "/tmp/example", "content": "x"}
        begin = grips.grip_run(
            "transport-roundtrip",
            self.parameters(
                "begin",
                _server_transport_client_scope=SHARED_SCOPE,
                target_tool_name="write",
                target_arguments=arguments,
            ),
            profile="operator",
            allow_mutation=True,
        )
        challenge = begin["output"]["challenge_receipt_sha256"]

        def dispatcher(tool_name, target_arguments, private_challenge):
            with roundtrip.execution_capability(private_challenge) as session:
                consumed = roundtrip.consume_verified(
                    client_scope=SHARED_SCOPE,
                    runtime_binding=BINDING,
                    tool_name=tool_name,
                    arguments_sha256=roundtrip.canonical_arguments_sha256(
                        target_arguments
                    ),
                )
                execution = roundtrip.execution_capability_snapshot(session)
            self.assertEqual(consumed["state"], "consumed")
            return {
                "target_result": {"called": True},
                "target_error": None,
                "execution": execution,
            }

        executed = grips.grip_run(
            "transport-roundtrip",
            self.parameters(
                "execute",
                _server_transport_client_scope=SHARED_SCOPE,
                challenge_receipt_sha256=challenge,
                target_tool_name="write",
                target_arguments=arguments,
            ),
            profile="operator",
            allow_mutation=True,
            transport_target_dispatcher=dispatcher,
        )
        self.assertEqual(executed["status"], "passed")
        self.assertEqual(executed["output"]["state"], "executed")
        self.assertTrue(executed["output"]["target_result"]["called"])
        self.assertIsNotNone(executed["output"]["consumption_receipt_sha256"])

    def test_mcp_handshake_does_not_depend_on_client_mutation_flag(self) -> None:
        base = _load_grabowski_mcp()
        observed: list[tuple[str, bool]] = []

        def fake_core(
            name, parameters, profile, allow_mutation, ctx, **_kwargs
        ):
            observed.append((name, allow_mutation))
            return {"status": "passed"}

        with (
            mock.patch.object(base, "_require_capability"),
            mock.patch.object(base, "_grip_run_core", side_effect=fake_core),
            mock.patch.object(
                base,
                "_validate_transport_roundtrip_target_tool",
                return_value="grabowski_terminal_run",
            ),
        ):
            result = asyncio.run(
                base._grip_run_mcp(
                    "transport-roundtrip",
                    {"action": "begin"},
                    allow_mutation=False,
                )
            )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(observed, [("transport-roundtrip", True)])

    def test_mcp_execute_claims_server_retained_target_from_challenge_only(self) -> None:
        base = _load_grabowski_mcp()
        challenge = "e" * 64
        original_arguments = {
            "request": {"action": "pickup_next", "owner_id": "chatgpt-operator"}
        }
        expected_arguments = {
            "request": {"action": "pickup_next", "owner_id": "chatgpt-operator"}
        }
        base._retain_pending_transport_target(
            challenge,
            tool_name="grabowski_bureau_pickup_execute",
            target_arguments=original_arguments,
            arguments_sha256=roundtrip.canonical_arguments_sha256(original_arguments),
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
        )
        original_arguments["request"]["owner_id"] = "mutated-after-retain"
        caller_parameters = {
            "action": "execute",
            "challenge_receipt_sha256": challenge,
        }
        observed: list[dict[str, object]] = []

        def fake_core(name, parameters, profile, allow_mutation, ctx, **_kwargs):
            observed.append(dict(parameters))
            return {"status": "passed", "name": name}

        with (
            mock.patch.object(base, "_require_capability"),
            mock.patch.object(
                base, "_transport_roundtrip_client_scope", return_value=SHARED_SCOPE
            ),
            mock.patch.object(
                base, "_transport_roundtrip_runtime_binding", return_value=BINDING
            ),
            mock.patch.object(base, "_grip_run_core", side_effect=fake_core),
            mock.patch.object(
                base,
                "_validate_transport_roundtrip_target_tool",
                return_value="grabowski_terminal_run",
            ),
        ):
            result = asyncio.run(
                base._grip_run_mcp(
                    "transport-roundtrip",
                    caller_parameters,
                    allow_mutation=False,
                )
            )

        self.assertEqual(result["status"], "passed")
        self.assertNotIn("target_tool_name", caller_parameters)
        self.assertNotIn("target_arguments", caller_parameters)
        self.assertEqual(len(observed), 1)
        self.assertEqual(
            observed[0]["target_tool_name"], "grabowski_bureau_pickup_execute"
        )
        self.assertEqual(observed[0]["target_arguments"], expected_arguments)
        with self.assertRaisesRegex(RuntimeError, "missing or expired"):
            base._claim_pending_transport_target(
                challenge, client_scope=SHARED_SCOPE, runtime_binding=BINDING
            )

    def test_mcp_execute_without_retained_target_requires_readback_when_unused_cannot_be_proven(self) -> None:
        base = _load_grabowski_mcp()
        challenge = "f" * 64
        with (
            mock.patch.object(base, "_require_capability"),
            mock.patch.object(
                base, "_transport_roundtrip_client_scope", return_value=SHARED_SCOPE
            ),
            mock.patch.object(
                base, "_transport_roundtrip_runtime_binding", return_value=BINDING
            ),
            mock.patch.object(
                base.grabowski_transport_roundtrip,
                "cancel_pending_execution_challenge",
                return_value={
                    "state": "consumed",
                    "cancelled": False,
                    "effect_possible": True,
                },
            ),
            mock.patch.object(base, "_grip_run_core") as core,
        ):
            result = asyncio.run(
                base._grip_run_mcp(
                    "transport-roundtrip",
                    {
                        "action": "execute",
                        "challenge_receipt_sha256": challenge,
                    },
                    allow_mutation=False,
                )
            )
        self.assertEqual(result["status"], "blocked")
        self.assertIn("target outcome may be unknown", result["output"]["error"])
        self.assertIn("target-specific readback", result["output"]["error"])
        core.assert_not_called()

    def test_mcp_execute_missing_target_can_retry_only_after_atomic_pending_cancel(self) -> None:
        base = _load_grabowski_mcp()
        challenge = "d" * 64
        with (
            mock.patch.object(base, "_require_capability"),
            mock.patch.object(
                base, "_transport_roundtrip_client_scope", return_value=SHARED_SCOPE
            ),
            mock.patch.object(
                base, "_transport_roundtrip_runtime_binding", return_value=BINDING
            ),
            mock.patch.object(
                base.grabowski_transport_roundtrip,
                "cancel_pending_execution_challenge",
                return_value={
                    "state": "cancelled_pending",
                    "cancelled": True,
                    "effect_possible": False,
                },
            ),
            mock.patch.object(base, "_grip_run_core") as core,
        ):
            result = asyncio.run(
                base._grip_run_mcp(
                    "transport-roundtrip",
                    {
                        "action": "execute",
                        "challenge_receipt_sha256": challenge,
                    },
                    allow_mutation=False,
                )
            )
        self.assertEqual(result["status"], "blocked")
        self.assertIn("atomically cancelled", result["output"]["error"])
        self.assertIn("retry the original target", result["output"]["error"])
        core.assert_not_called()

    def test_mcp_execute_rejects_second_claim_while_first_is_in_flight(self) -> None:
        base = _load_grabowski_mcp()
        challenge = "c" * 64
        arguments = {"request": {"action": "pickup_next"}}
        base._retain_pending_transport_target(
            challenge,
            tool_name="grabowski_bureau_pickup_execute",
            target_arguments=arguments,
            arguments_sha256=roundtrip.canonical_arguments_sha256(arguments),
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
        )
        base._claim_pending_transport_target(
            challenge, client_scope=SHARED_SCOPE, runtime_binding=BINDING
        )
        try:
            with (
                mock.patch.object(base, "_require_capability"),
                mock.patch.object(
                    base, "_transport_roundtrip_client_scope", return_value=SHARED_SCOPE
                ),
                mock.patch.object(
                    base, "_transport_roundtrip_runtime_binding", return_value=BINDING
                ),
                mock.patch.object(base, "_grip_run_core") as core,
            ):
                result = asyncio.run(
                    base._grip_run_mcp(
                        "transport-roundtrip",
                        {
                            "action": "execute",
                            "challenge_receipt_sha256": challenge,
                        },
                        allow_mutation=False,
                    )
                )
            self.assertEqual(result["status"], "blocked")
            self.assertIn("in flight", result["output"]["error"])
            core.assert_not_called()
        finally:
            base._discard_pending_transport_target(challenge)

    def test_retained_target_pool_evicts_oldest_pending_for_memory_bound(self) -> None:
        base = _load_grabowski_mcp()
        first = {"payload": "a" * 64}
        second = {"payload": "b" * 64}
        first_bytes = len(
            json.dumps(first, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        with mock.patch.object(
            base, "_RETAINED_TRANSPORT_TARGET_TOTAL_MAX_BYTES", first_bytes + 1
        ):
            base._retain_pending_transport_target(
                "1" * 64,
                tool_name="write",
                target_arguments=first,
                arguments_sha256=roundtrip.canonical_arguments_sha256(first),
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
            )
            base._retain_pending_transport_target(
                "2" * 64,
                tool_name="write",
                target_arguments=second,
                arguments_sha256=roundtrip.canonical_arguments_sha256(second),
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
            )
            with self.assertRaisesRegex(RuntimeError, "missing or expired"):
                base._claim_pending_transport_target(
                    "1" * 64, client_scope=SHARED_SCOPE, runtime_binding=BINDING
                )
            claimed = base._claim_pending_transport_target(
                "2" * 64, client_scope=SHARED_SCOPE, runtime_binding=BINDING
            )
            self.assertEqual(claimed["target_arguments"], second)

    def test_retained_target_pool_never_evicts_inflight_target(self) -> None:
        base = _load_grabowski_mcp()
        first = {"payload": "a"}
        second = {"payload": "b"}
        with mock.patch.object(base, "_RETAINED_TRANSPORT_TARGET_MAX", 1):
            base._retain_pending_transport_target(
                "1" * 64,
                tool_name="write",
                target_arguments=first,
                arguments_sha256=roundtrip.canonical_arguments_sha256(first),
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
            )
            base._claim_pending_transport_target(
                "1" * 64, client_scope=SHARED_SCOPE, runtime_binding=BINDING
            )
            try:
                with self.assertRaisesRegex(RuntimeError, "only in-flight targets"):
                    base._retain_pending_transport_target(
                        "2" * 64,
                        tool_name="write",
                        target_arguments=second,
                        arguments_sha256=roundtrip.canonical_arguments_sha256(second),
                        client_scope=SHARED_SCOPE,
                        runtime_binding=BINDING,
                    )
            finally:
                base._discard_pending_transport_target("1" * 64)

    def test_mcp_handshake_exemption_does_not_leak_to_other_grips(self) -> None:
        base = _load_grabowski_mcp()
        observed: list[bool] = []

        def fake_core(
            name, parameters, profile, allow_mutation, ctx, **_kwargs
        ):
            observed.append(allow_mutation)
            return {"status": "passed", "name": name}

        self.assertFalse(
            base._mcp_effective_grip_mutation_permission(
                "worktree-ensure", False
            )
        )
        self.assertTrue(
            base._mcp_effective_grip_mutation_permission(
                "worktree-ensure", True
            )
        )
        with base.grabowski_transport_roundtrip.execution_capability("a" * 64):
            self.assertFalse(
                base._mcp_effective_grip_mutation_permission(
                    "worktree-ensure", False
                )
            )
        with mock.patch.object(base, "_require_capability"), mock.patch.object(
            base, "_grip_run_core", side_effect=fake_core
        ):
            result = asyncio.run(
                base._grip_run_mcp(
                    "worktree-ensure", {}, allow_mutation=False
                )
            )

        self.assertEqual(result["status"], "passed")
        self.assertEqual(observed, [False])

    def test_grip_requires_mutation_permission_and_rejects_extra_fields(self) -> None:
        denied = grips.grip_run(
            "transport-roundtrip",
            self.parameters("begin"),
            profile="operator",
            allow_mutation=False,
        )
        self.assertEqual(denied["status"], "blocked")
        self.assertTrue(denied["output"]["requires_allow_mutation"])
        extra = grips.grip_run(
            "transport-roundtrip",
            self.parameters("begin", unexpected=True),
            profile="operator",
            allow_mutation=True,
        )
        self.assertEqual(extra["status"], "blocked")
        self.assertIn("unknown transport roundtrip field", extra["output"]["error"])


class ConnectorCapabilityScopeTests(unittest.TestCase):
    TOKEN_A = "A" * 43
    TOKEN_B = "B" * 43
    TOKEN_UNKNOWN = "C" * 43

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "transport-connectors"
        self.base = _load_grabowski_mcp()
        self.base._TRANSPORT_CONNECTOR_IDENTITY_ROOT = self.root
        self.base._TRANSPORT_CONNECTOR_ENFORCEMENT_MARKER = (
            self.root / "require-identity"
        )
        self.base._TRANSPORT_SERVER_INSTANCE_ID = "server-instance-a"
        state_root = Path(temporary.name) / "roundtrip-state"
        self.state_root_patch = mock.patch.object(roundtrip, "STATE_ROOT", state_root)
        self.lock_path_patch = mock.patch.object(
            roundtrip, "LOCK_PATH", state_root / ".lock"
        )
        self.state_root_patch.start()
        self.lock_path_patch.start()
        self.addCleanup(self.state_root_patch.stop)
        self.addCleanup(self.lock_path_patch.stop)

    def enroll(self, **tokens: str) -> None:
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        for connector_id, token in tokens.items():
            path = self.root / f"{connector_id}.token"
            path.write_text(token, encoding="ascii")
            os.chmod(path, 0o600)

    def require_identity(self) -> None:
        marker = self.root / "require-identity"
        marker.write_text("required-v1", encoding="ascii")
        os.chmod(marker, 0o600)

    def context(
        self,
        token: str | None = None,
        *,
        client_id: str = "client-meta",
        session_id: str = "session-meta",
    ) -> object:
        headers: dict[str, str] = {}
        if token is not None:
            headers[self.base._TRANSPORT_CONNECTOR_CAPABILITY_HEADER] = token
        request = types.SimpleNamespace(headers=headers)
        request_context = types.SimpleNamespace(request=request)
        return types.SimpleNamespace(
            client_id=client_id,
            session_id=session_id,
            request_context=request_context,
        )

    def test_client_declared_meta_is_not_transport_authority(self) -> None:
        scope = self.base._transport_roundtrip_client_scope(
            self.context(client_id="spoofed-client", session_id="spoofed-session")
        )
        self.assertEqual(scope, SHARED_SCOPE)

    def test_same_connector_capability_survives_meta_and_session_churn(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        first = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A, client_id="one", session_id="session-one")
        )
        second = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A, client_id="two", session_id="session-two")
        )
        self.assertEqual(first["kind"], "connector_capability")
        self.assertEqual(first, second)
        self.assertNotIn(self.TOKEN_A, first["label"])

    def test_distinct_tunnel_capabilities_are_isolated(self) -> None:
        self.enroll(primary=self.TOKEN_A, johannes=self.TOKEN_B)
        primary = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A)
        )
        johannes = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_B)
        )
        self.assertEqual(primary["kind"], "connector_capability")
        self.assertEqual(johannes["kind"], "connector_capability")
        self.assertNotEqual(primary["label"], johannes["label"])

    def test_server_restart_changes_connector_scope(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        first = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A)
        )
        self.base._TRANSPORT_SERVER_INSTANCE_ID = "server-instance-b"
        second = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A)
        )
        self.assertNotEqual(first["label"], second["label"])

    def test_unknown_connector_capability_fails_closed(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        with self.assertRaisesRegex(RuntimeError, "not enrolled"):
            self.base._transport_roundtrip_client_scope(
                self.context(self.TOKEN_UNKNOWN)
            )

    def test_enforcement_rejects_headerless_mutation_scope(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        self.require_identity()
        with self.assertRaisesRegex(RuntimeError, "identity is required"):
            self.base._transport_roundtrip_client_scope(self.context())

    def test_status_projection_remains_readable_without_identity(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        self.require_identity()
        projected = self.base._transport_roundtrip_status(self.context())
        self.assertEqual(projected["state"], "connector_identity_required")
        self.assertFalse(projected["mutation_gate_open"])


    def test_same_connector_completes_three_call_handshake_across_context_churn(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        arguments = {"path": "/tmp/t142", "content": "ok"}
        intent = {
            "tool_name": "write",
            "arguments_sha256": roundtrip.canonical_arguments_sha256(arguments),
        }
        begin_scope = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A, client_id="begin", session_id="session-a")
        )
        begun = roundtrip.begin(
            client_scope=begin_scope,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=100,
        )
        ack_scope = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A, client_id="ack", session_id="session-b")
        )
        acked = roundtrip.acknowledge(
            client_scope=ack_scope,
            challenge_receipt_sha256=begun["challenge_receipt_sha256"],
            runtime_binding=BINDING,
            now_unix=101,
        )
        self.assertEqual(acked["state"], "verified")
        consume_scope = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A, client_id="consume", session_id="session-c")
        )
        consumed = roundtrip.consume_verified(
            client_scope=consume_scope,
            runtime_binding=BINDING,
            now_unix=102,
            **intent,
        )
        self.assertTrue(consumed["consumption_receipt_sha256"])
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            roundtrip.consume_verified(
                client_scope=consume_scope,
                runtime_binding=BINDING,
                now_unix=103,
                **intent,
            )

    def test_foreign_connector_cannot_ack_or_consume_owner_handshake(self) -> None:
        self.enroll(primary=self.TOKEN_A, johannes=self.TOKEN_B)
        primary = self.base._transport_roundtrip_client_scope(self.context(self.TOKEN_A))
        foreign = self.base._transport_roundtrip_client_scope(self.context(self.TOKEN_B))
        intent = {"tool_name": "write", "arguments_sha256": "d" * 64}
        begun = roundtrip.begin(
            client_scope=primary,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=100,
        )
        challenge = begun["challenge_receipt_sha256"]
        with self.assertRaises(roundtrip.TransportRoundtripError):
            roundtrip.acknowledge(
                client_scope=foreign,
                challenge_receipt_sha256=challenge,
                runtime_binding=BINDING,
                now_unix=101,
            )
        roundtrip.acknowledge(
            client_scope=primary,
            challenge_receipt_sha256=challenge,
            runtime_binding=BINDING,
            now_unix=101,
        )
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            roundtrip.consume_verified(
                client_scope=foreign,
                runtime_binding=BINDING,
                now_unix=102,
                **intent,
            )
        consumed = roundtrip.consume_verified(
            client_scope=primary,
            runtime_binding=BINDING,
            now_unix=102,
            **intent,
        )
        self.assertTrue(consumed["consumption_receipt_sha256"])

    def test_server_restart_invalidates_verified_connector_scope(self) -> None:
        self.enroll(primary=self.TOKEN_A)
        before_restart = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A)
        )
        intent = {"tool_name": "write", "arguments_sha256": "f" * 64}
        begun = roundtrip.begin(
            client_scope=before_restart,
            runtime_binding=BINDING,
            mutation_intent=intent,
            now_unix=100,
        )
        roundtrip.acknowledge(
            client_scope=before_restart,
            challenge_receipt_sha256=begun["challenge_receipt_sha256"],
            runtime_binding=BINDING,
            now_unix=101,
        )
        self.base._TRANSPORT_SERVER_INSTANCE_ID = "server-instance-b"
        after_restart = self.base._transport_roundtrip_client_scope(
            self.context(self.TOKEN_A)
        )
        self.assertNotEqual(before_restart, after_restart)
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            roundtrip.consume_verified(
                client_scope=after_restart,
                runtime_binding=BINDING,
                now_unix=102,
                **intent,
            )


class CentralTransportGateTests(unittest.TestCase):
    @staticmethod
    def mutating_tool() -> object:
        return types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )

    def configured_operator(self):
        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = (
            lambda context: (
                META_SCOPE
                if getattr(context, "client_id", None)
                else SHARED_SCOPE
            )
        )
        operator.mcp._tool_manager.get_tool = lambda _name: self.mutating_tool()
        operator._configure_http_runtime()
        return operator

    def test_mutating_call_is_rejected_before_effect_without_verification(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            side_effect=roundtrip.TransportRoundtripRequired("handshake required"),
        ) as consume_verified:
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ) as raised:
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        self.assertIn("action=ack", str(raised.exception))
        self.assertIn("retry the exact mutation", str(raised.exception))
        consume_verified.assert_called_once_with(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=roundtrip.canonical_arguments_sha256({}),
        )
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_shared_unlabeled_call_directs_atomic_execute_not_ack(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace()
        challenge = "a" * 64
        with (
            mock.patch.object(
                operator.grabowski_transport_roundtrip,
                "consume_verified",
                side_effect=roundtrip.TransportRoundtripRequired("handshake required"),
            ) as consume_verified,
            mock.patch.object(
                operator.grabowski_transport_roundtrip,
                "begin",
                return_value={
                    "state": "challenge_pending",
                    "challenge_receipt_sha256": challenge,
                },
            ),
            mock.patch.object(
                operator.base, "_retain_pending_transport_target"
            ) as retain_target,
        ):
            with self.assertRaisesRegex(RuntimeError, "action=execute") as raised:
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        message = str(raised.exception)
        self.assertIn(f"challenge_receipt_sha256={challenge}", message)
        self.assertIn("exact target is retained server-side", message)
        self.assertIn("do not include target_tool_name or target_arguments", message)
        self.assertIn("do not retry the original target separately", message)
        self.assertNotIn("target_tool_name=write", message)
        self.assertNotIn("action=ack", message)
        digest = roundtrip.canonical_arguments_sha256({})
        consume_verified.assert_called_once_with(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=digest,
        )
        retain_target.assert_called_once_with(
            challenge,
            tool_name="write",
            target_arguments={},
            arguments_sha256=digest,
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
        )
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_verified_mutation_consumes_receipt_and_runs(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        arguments = {"path": "/tmp/example"}
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ) as consume_verified:
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool("write", arguments, context)
            )
        self.assertTrue(result["called"])
        consume_verified.assert_called_once_with(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=roundtrip.canonical_arguments_sha256(arguments),
        )

    def test_admission_failure_after_consume_still_runs_domain_tool(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        arguments = {"path": "/tmp/example"}
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ) as consume_verified:
            with mock.patch.object(
                operator.grabowski_effect_interceptor,
                "admit_mutation",
                side_effect=RuntimeError("audit unavailable"),
            ) as admit_mutation:
                with mock.patch.object(
                    operator.grabowski_effect_interceptor,
                    "record_success_best_effort",
                ) as record_success:
                    result = asyncio.run(
                        operator.mcp._tool_manager.call_tool(
                            "write", arguments, context
                        )
                    )
        self.assertTrue(result["called"])
        consume_verified.assert_called_once()
        admit_mutation.assert_called_once()
        record_success.assert_not_called()
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_sync_executor_submit_failure_records_exception_then_reraises(self) -> None:
        operator = self.configured_operator()

        class RejectingExecutor:
            def submit(self, *args, **kwargs):
                raise RuntimeError("executor rejected")

        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._SYNC_TOOL_EXECUTOR = RejectingExecutor()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        admission = {
            "schema_version": 1,
            "kind": "grabowski.effect_admission",
            "request_id": "a" * 32,
            "admission_sha256": "b" * 64,
        }
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ):
            with mock.patch.object(
                operator.grabowski_effect_interceptor,
                "admit_mutation",
                return_value=admission,
            ):
                with mock.patch.object(
                    operator.grabowski_effect_interceptor,
                    "record_exception_best_effort",
                ) as record_exception:
                    with self.assertRaisesRegex(
                        RuntimeError, "executor rejected"
                    ):
                        asyncio.run(
                            operator.mcp._tool_manager.call_tool(
                                "write", {}, context
                            )
                        )
        record_exception.assert_called_once()
        self.assertIs(record_exception.call_args.args[0], admission)
        self.assertIsInstance(record_exception.call_args.args[1], RuntimeError)
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_wrap_failure_after_submit_keeps_admission_until_worker_callback(
        self,
    ) -> None:
        operator = self.configured_operator()
        held = concurrent.futures.Future()

        class HoldingExecutor:
            def submit(self, *args, **kwargs):
                return held

        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._SYNC_TOOL_EXECUTOR = HoldingExecutor()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        admission = {
            "schema_version": 1,
            "kind": "grabowski.effect_admission",
            "request_id": "a" * 32,
            "admission_sha256": "b" * 64,
        }
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ), mock.patch.object(
            operator.grabowski_effect_interceptor,
            "admit_mutation",
            return_value=admission,
        ), mock.patch.object(
            operator.grabowski_effect_interceptor,
            "record_exception_best_effort",
        ) as record_exception, mock.patch.object(
            operator.asyncio,
            "wrap_future",
            side_effect=RuntimeError("wrap failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "wrap failed"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool("write", {}, context)
                )
        record_exception.assert_called_once()
        self.assertIs(record_exception.call_args.args[0], admission)
        # Outer finally must not release while the submitted worker may run.
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 1)
        held.set_result({"called": True})
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_callback_registration_failure_after_submit_does_not_release_in_finally(
        self,
    ) -> None:
        operator = self.configured_operator()

        class FutureRejectingCallback(concurrent.futures.Future):
            def add_done_callback(self, fn):  # type: ignore[override]
                raise RuntimeError("callback registration failed")

        held = FutureRejectingCallback()

        class HoldingExecutor:
            def submit(self, *args, **kwargs):
                return held

        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._SYNC_TOOL_EXECUTOR = HoldingExecutor()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        admission = {
            "schema_version": 1,
            "kind": "grabowski.effect_admission",
            "request_id": "a" * 32,
            "admission_sha256": "b" * 64,
        }
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ), mock.patch.object(
            operator.grabowski_effect_interceptor,
            "admit_mutation",
            return_value=admission,
        ), mock.patch.object(
            operator.grabowski_effect_interceptor,
            "record_exception_best_effort",
        ) as record_exception:
            with self.assertRaisesRegex(
                RuntimeError, "callback registration failed"
            ):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool("write", {}, context)
                )
        record_exception.assert_called_once()
        # Conservative hold: no outer finally release while worker may still run.
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 1)

    def test_admission_keyboard_interrupt_does_not_start_domain_tool(self) -> None:
        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = (
            lambda context: (
                META_SCOPE
                if getattr(context, "client_id", None)
                else SHARED_SCOPE
            )
        )
        domain_calls: list[object] = []

        async def original_call(*args, **kwargs):
            domain_calls.append({"args": args, "kwargs": kwargs})
            return {"called": True}

        operator.mcp._tool_manager.call_tool = original_call
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ), mock.patch.object(
            operator.grabowski_effect_interceptor,
            "admit_mutation",
            side_effect=KeyboardInterrupt("interrupted"),
        ):
            with self.assertRaises(KeyboardInterrupt):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool("write", {}, context)
                )
        self.assertEqual(domain_calls, [])
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_atomic_dispatch_classifies_mcp_error_result(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        base = _load_grabowski_mcp()
        transport = base.grabowski_transport_roundtrip
        arguments = {"sequence": 1}
        digest = transport.canonical_arguments_sha256(arguments)

        async def error_result(_name, _arguments, _context):
            transport.consume_verified(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                tool_name="write",
                arguments_sha256=digest,
            )
            return types.SimpleNamespace(
                isError=True,
                structuredContent={
                    "kind": "grabowski_bureau_pickup_error",
                    "code": "work-admission-blocked",
                },
            )

        base.mcp._tool_manager = types.SimpleNamespace(
            get_tool=lambda _name: self.mutating_tool(),
            call_tool=error_result,
        )
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
        ):
            begun = transport.begin(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "write",
                    "arguments_sha256": digest,
                },
            )
            challenge = begun["challenge_receipt_sha256"]
            transport.reserve_execution(
                client_scope=SHARED_SCOPE,
                challenge_receipt_sha256=challenge,
                runtime_binding=BINDING,
                tool_name="write",
                arguments_sha256=digest,
            )
            result = asyncio.run(
                base._dispatch_atomic_transport_target(
                    "write", arguments, challenge, None
                )
            )
        self.assertEqual(result["target_error"]["type"], "SimpleNamespace")
        self.assertEqual(
            result["target_error"]["structured_content"]["code"],
            "work-admission-blocked",
        )
        self.assertIsNotNone(
            result["execution"]["consumption_receipt_sha256"]
        )

    def test_stateless_shared_scope_admits_two_independent_handshakes(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        operator = self.configured_operator()
        transport = operator.grabowski_transport_roundtrip
        context = types.SimpleNamespace(client_id=None)
        arguments = {"sequence": 1}
        digest = transport.canonical_arguments_sha256(arguments)
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
        ):
            begun = transport.begin(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "write",
                    "arguments_sha256": digest,
                },
            )
            challenge = begun["challenge_receipt_sha256"]
            transport.reserve_execution(
                client_scope=SHARED_SCOPE,
                challenge_receipt_sha256=challenge,
                runtime_binding=BINDING,
                tool_name="write",
                arguments_sha256=digest,
            )
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "write", arguments, context
                    )
                )
            with transport.execution_capability(challenge) as session:
                result = asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "write", arguments, context
                    )
                )
                execution = transport.execution_capability_snapshot(session)
        self.assertTrue(result["called"])
        self.assertIsNotNone(execution["consumption_receipt_sha256"])

    def test_bound_shared_verification_bootstraps_exact_handshake_without_theft(
        self,
    ) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        operator = self.configured_operator()
        transport = operator.grabowski_transport_roundtrip
        context = types.SimpleNamespace(client_id=None)
        arguments = {"sequence": 1}
        digest = transport.canonical_arguments_sha256(arguments)
        intent = {"tool_name": "write", "arguments_sha256": digest}
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
        ):
            first = transport.begin(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                mutation_intent=intent,
            )
            second = transport.begin(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                mutation_intent=intent,
            )
            first_challenge = first["challenge_receipt_sha256"]
            second_challenge = second["challenge_receipt_sha256"]
            self.assertNotEqual(first_challenge, second_challenge)
            for challenge in (first_challenge, second_challenge):
                transport.reserve_execution(
                    client_scope=SHARED_SCOPE,
                    challenge_receipt_sha256=challenge,
                    runtime_binding=BINDING,
                    tool_name="write",
                    arguments_sha256=digest,
                )
            with transport.execution_capability(first_challenge):
                first_result = asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "write", arguments, context
                    )
                )
            with transport.execution_capability(first_challenge):
                with self.assertRaisesRegex(
                    RuntimeError, "fresh intent-bound transport verification required"
                ):
                    asyncio.run(
                        operator.mcp._tool_manager.call_tool(
                            "write", arguments, context
                        )
                    )
            status = transport.status(
                client_scope=SHARED_SCOPE, runtime_binding=BINDING
            )
            self.assertEqual(status["verified_receipt_count"], 1)
            with transport.execution_capability(second_challenge):
                second_result = asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "write", arguments, context
                    )
                )
        self.assertTrue(first_result["called"])
        self.assertTrue(second_result["called"])

    def test_registered_read_only_grip_skips_mutation_roundtrip(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id=None)
        arguments = {
            "name": "situation",
            "parameters": {"repo": "/tmp/example"},
            "profile": "operator",
            "allow_mutation": False,
        }
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            side_effect=AssertionError("read-only grip reached mutation gate"),
        ) as consume_verified:
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "grip_run", arguments, context
                )
            )
        self.assertTrue(result["called"])
        consume_verified.assert_not_called()

    def test_registered_mutating_grip_still_requires_exact_roundtrip(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id=None)
        arguments = {
            "name": "worktree-ensure",
            "parameters": {},
            "profile": "operator",
            "allow_mutation": True,
        }
        with (
            mock.patch.object(
                operator.grabowski_transport_roundtrip,
                "consume_verified",
                side_effect=roundtrip.TransportRoundtripRequired("handshake required"),
            ) as consume_verified,
            mock.patch.object(
                operator.grabowski_transport_roundtrip,
                "begin",
                return_value={
                    "state": "challenge_pending",
                    "challenge_receipt_sha256": "a" * 64,
                },
            ),
            mock.patch.object(operator.base, "_retain_pending_transport_target"),
        ):
            with self.assertRaisesRegex(RuntimeError, "action=execute"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "grip_run", arguments, context
                    )
                )
        consume_verified.assert_called_once()

    def test_unknown_grip_is_not_exempt_from_mutation_roundtrip(self) -> None:
        operator = self.configured_operator()
        self.assertFalse(
            operator._transport_roundtrip_exempt_call(
                "grip_run", {"name": "not-a-registered-grip"}
            )
        )

    def test_handshake_grip_is_narrowly_exempt(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            side_effect=AssertionError("handshake exemption called gate"),
        ) as consume_verified:
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "grip_run",
                    {
                        "name": "transport-roundtrip",
                        "parameters": {"action": "begin"},
                        "allow_mutation": True,
                    },
                    context,
                )
            )
        self.assertTrue(result["called"])
        consume_verified.assert_not_called()

    def test_non_marker_deployment_status_is_not_broadly_exempt(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            side_effect=roundtrip.TransportRoundtripRequired("handshake required"),
        ) as consume_verified:
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        operator.deployment_observer.OPERATION, {}, context
                    )
                )
        consume_verified.assert_called_once_with(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name=operator.deployment_observer.OPERATION,
            arguments_sha256=roundtrip.canonical_arguments_sha256({}),
        )
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_unknown_tool_annotation_fails_closed_before_effect(self) -> None:
        operator = _load_operator_module()
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=None,
        )
        operator._configure_http_runtime()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        with self.assertRaisesRegex(RuntimeError, "explicit readOnlyHint"):
            asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "unknown-contract-tool", {}, context
                )
            )

    def test_missing_meta_uses_explicit_shared_unlabeled_scope(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id=None)
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={
                "state": "consumed",
                "runtime_binding_sha256": roundtrip._sha256_json(BINDING),
                "consumption_receipt_sha256": "d" * 64,
            },
        ) as consume_verified:
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool("write", {}, context)
            )
        self.assertTrue(result["called"])
        consume_verified.assert_called_once_with(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=roundtrip.canonical_arguments_sha256({}),
        )


class StaleServingProcessGateTests(unittest.TestCase):
    """A process older than the deployed release must not mutate."""

    PROCESS_RELEASE = "process-release-1"
    PROCESS_HEAD = "d" * 40
    DEPLOYED_RELEASE = "deployed-release-2"
    DEPLOYED_HEAD = "e" * 40

    def setUp(self) -> None:
        serving.reset_for_tests()
        self.addCleanup(serving.reset_for_tests)

    def configured_operator(self, deployed_release, deployed_head):
        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = lambda context: META_SCOPE
        operator.base._deployment_metadata = lambda: {
            "release_id": deployed_release,
            "repo_head": deployed_head,
        }
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        return operator

    def test_stale_process_is_refused_before_the_transport_handshake(self) -> None:
        serving.freeze(self.PROCESS_RELEASE, self.PROCESS_HEAD)
        operator = self.configured_operator(self.DEPLOYED_RELEASE, self.DEPLOYED_HEAD)
        context = types.SimpleNamespace(client_id="c", session_id="session-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip, "consume_verified"
        ) as consume_verified:
            with self.assertRaisesRegex(RuntimeError, "Reconnect the MCP connector"):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        consume_verified.assert_not_called()
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_current_process_still_reaches_the_transport_handshake(self) -> None:
        serving.freeze(self.DEPLOYED_RELEASE, self.DEPLOYED_HEAD)
        operator = self.configured_operator(self.DEPLOYED_RELEASE, self.DEPLOYED_HEAD)
        context = types.SimpleNamespace(client_id="c", session_id="session-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            side_effect=roundtrip.TransportRoundtripRequired("handshake required"),
        ) as consume_verified:
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        consume_verified.assert_called_once()

    def test_unknown_deployed_identity_does_not_block(self) -> None:
        serving.freeze(self.PROCESS_RELEASE, self.PROCESS_HEAD)
        operator = self.configured_operator(None, None)
        context = types.SimpleNamespace(client_id="c", session_id="session-1")
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            side_effect=roundtrip.TransportRoundtripRequired("handshake required"),
        ) as consume_verified:
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        consume_verified.assert_called_once()

    def test_read_only_tools_are_unaffected_by_a_stale_process(self) -> None:
        serving.freeze(self.PROCESS_RELEASE, self.PROCESS_HEAD)
        operator = self.configured_operator(self.DEPLOYED_RELEASE, self.DEPLOYED_HEAD)
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=True),
        )
        operator._require_transport_roundtrip_for_tool(
            tool_name="read",
            arguments={},
            context=types.SimpleNamespace(client_id="c", session_id="session-1"),
            tool=operator.mcp._tool_manager.get_tool("read"),
        )


class SharedPartitionEffectBoundaryTests(unittest.TestCase):
    """Bearer-bound atomic admission for the shared unlabeled partition."""

    INTENT_ARGUMENTS = {"path": "/tmp/shared-target"}

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "state"
        self.root_patch = mock.patch.object(roundtrip, "STATE_ROOT", self.root)
        self.lock_patch = mock.patch.object(
            roundtrip, "LOCK_PATH", self.root / ".lock"
        )
        self.root_patch.start()
        self.lock_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.lock_patch.stop)

    def bind(self, arguments: dict[str, object]) -> str:
        digest = roundtrip.canonical_arguments_sha256(arguments)
        begun = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": digest,
            },
        )
        challenge = begun["challenge_receipt_sha256"]
        roundtrip.reserve_execution(
            client_scope=SHARED_SCOPE,
            challenge_receipt_sha256=challenge,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=digest,
        )
        return challenge

    def consume(
        self, challenge: str, arguments: dict[str, object]
    ) -> dict[str, object]:
        with roundtrip.execution_capability(challenge):
            return roundtrip.consume_verified(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                tool_name="write",
                arguments_sha256=roundtrip.canonical_arguments_sha256(arguments),
            )

    def test_shared_scope_is_declared_a_partition_not_an_identity(self) -> None:
        challenge = self.bind(self.INTENT_ARGUMENTS)
        consumed = self.consume(challenge, self.INTENT_ARGUMENTS)
        self.assertTrue(consumed["execution_capability_bound"])
        self.assertTrue(
            any(
                item.startswith("caller identity: shared_unlabeled remains")
                for item in consumed["does_not_establish"]
            )
        )

    def test_second_unlabeled_caller_of_one_intent_is_refused(self) -> None:
        challenge = self.bind(self.INTENT_ARGUMENTS)
        self.consume(challenge, self.INTENT_ARGUMENTS)
        with roundtrip.execution_capability(challenge):
            with self.assertRaises(roundtrip.TransportRoundtripRequired):
                roundtrip.consume_verified(
                    client_scope=SHARED_SCOPE,
                    runtime_binding=BINDING,
                    tool_name="write",
                    arguments_sha256=roundtrip.canonical_arguments_sha256(
                        self.INTENT_ARGUMENTS
                    ),
                )

    def test_each_admission_carries_a_distinct_consumption_receipt(self) -> None:
        first_challenge = self.bind(self.INTENT_ARGUMENTS)
        first = self.consume(first_challenge, self.INTENT_ARGUMENTS)
        second_challenge = self.bind(self.INTENT_ARGUMENTS)
        second = self.consume(second_challenge, self.INTENT_ARGUMENTS)
        self.assertNotEqual(first_challenge, second_challenge)
        self.assertNotEqual(
            first["consumption_receipt_sha256"],
            second["consumption_receipt_sha256"],
        )

    def test_a_failed_effect_leaves_no_reusable_proof(self) -> None:
        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = lambda context: SHARED_SCOPE

        async def exploding_effect(*_args: object, **_kwargs: object):
            raise RuntimeError("effect failed after admission")

        operator.mcp._tool_manager.call_tool = exploding_effect
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        gated = operator.mcp._tool_manager.call_tool
        challenge = self.bind(self.INTENT_ARGUMENTS)
        with (
            mock.patch.object(
                operator.grabowski_transport_roundtrip, "STATE_ROOT", self.root
            ),
            mock.patch.object(
                operator.grabowski_transport_roundtrip,
                "LOCK_PATH",
                self.root / ".lock",
            ),
            roundtrip.execution_capability(challenge),
        ):
            with self.assertRaisesRegex(RuntimeError, "effect failed after admission"):
                asyncio.run(
                    gated(
                        "write",
                        dict(self.INTENT_ARGUMENTS),
                        types.SimpleNamespace(client_id=None),
                    )
                )
            with self.assertRaises(roundtrip.TransportRoundtripRequired):
                self.consume(challenge, self.INTENT_ARGUMENTS)
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import grabowski_grips as grips
import grabowski_transport_roundtrip as roundtrip
import grabowski_serving_process as serving
from tests.test_operator_contract import _load_operator_module


BINDING = {
    "release_id": "release-1",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}
META_SCOPE = {"kind": "connector_session", "label": "mcp-client-1-session-1"}
OTHER_SCOPE = {"kind": "connector_session", "label": "mcp-client-2-session-2"}
SESSION_POOL_SCOPE = {
    "kind": "connector_session",
    "label": "mcp-client-pool-session",
}
# Alias for older concurrent-handshake tests inside one session.
SHARED_SCOPE = SESSION_POOL_SCOPE



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
        self.assertEqual(ack["output"]["client_scope_kind"], "connector_session")
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
        self.assertEqual(contract["version"], "1.2")
        self.assertIn("exact-target-bound", contract["acceptance_ids"])
        self.assertIn("connector-session-bound", contract["acceptance_ids"])
        for fragment in ("target_tool_name", "target_arguments"):
            self.assertIn(fragment, contract["summary"])
            self.assertIn(fragment, contract["recovery_path"])
        preconditions = " | ".join(contract["preconditions"])
        self.assertIn(
            "action=begin requires target_tool_name and target_arguments together",
            preconditions,
        )
        self.assertIn("action=ack requires challenge_receipt_sha256", preconditions)
        # The conditional fields must not become statically required, or ack
        # would be forced to carry begin-only fields.
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
        self.assertIn(
            "target_tool_name and target_arguments together",
            blocked["output"]["error"],
        )

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
        operator.base._transport_roundtrip_client_scope = lambda context: META_SCOPE
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
            ):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        consume_verified.assert_called_once_with(
            client_scope=META_SCOPE,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=roundtrip.canonical_arguments_sha256({}),
        )
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)

    def test_verified_mutation_consumes_receipt_and_runs(self) -> None:
        operator = self.configured_operator()
        context = types.SimpleNamespace(client_id="mcp-client-1")
        arguments = {"path": "/tmp/example"}
        with mock.patch.object(
            operator.grabowski_transport_roundtrip,
            "consume_verified",
            return_value={"state": "consumed"},
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

    def test_session_pool_admits_two_independent_handshakes(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        operator = self.configured_operator()
        operator.base._transport_roundtrip_client_scope = lambda context: SHARED_SCOPE
        transport = operator.grabowski_transport_roundtrip
        with mock.patch.object(
            transport, "STATE_ROOT", root
        ), mock.patch.object(
            transport, "LOCK_PATH", root / ".lock"
        ):
            challenges = [
                transport.begin(
                    client_scope=SHARED_SCOPE,
                    runtime_binding=BINDING,
                    mutation_intent={
                        "tool_name": "write",
                        "arguments_sha256": transport.canonical_arguments_sha256(
                            {"sequence": sequence}
                        ),
                    },
                )["challenge_receipt_sha256"]
                for sequence in (1, 2)
            ]
            for challenge in challenges:
                transport.acknowledge(
                    client_scope=SHARED_SCOPE,
                    challenge_receipt_sha256=challenge,
                    runtime_binding=BINDING,
                )

            context = types.SimpleNamespace(
                client_id="pool", session_id="session-pool"
            )
            first = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "write", {"sequence": 1}, context
                )
            )
            second = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "write", {"sequence": 2}, context
                )
            )
            self.assertTrue(first["called"])
            self.assertTrue(second["called"])
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "write", {"sequence": 3}, context
                    )
                )

    def test_bound_session_verification_bootstraps_exact_handshake_without_theft(
        self,
    ) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        operator = self.configured_operator()
        operator.base._transport_roundtrip_client_scope = lambda context: SHARED_SCOPE
        transport = operator.grabowski_transport_roundtrip
        context = types.SimpleNamespace(client_id="pool", session_id="session-pool")
        arguments = {"sequence": 1}
        arguments_sha256 = transport.canonical_arguments_sha256(arguments)
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
        ):
            begin = transport.begin(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "write",
                    "arguments_sha256": arguments_sha256,
                },
            )
            transport.acknowledge(
                client_scope=SHARED_SCOPE,
                challenge_receipt_sha256=begin["challenge_receipt_sha256"],
                runtime_binding=BINDING,
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "fresh intent-bound transport verification required",
            ) as blocked:
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "other-write", arguments, context
                    )
                )
            message = str(blocked.exception)
            challenge = message.split("challenge_receipt_sha256=", 1)[1].split()[0]
            with self.assertRaisesRegex(
                RuntimeError,
                "fresh intent-bound transport verification required",
            ) as replayed:
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "other-write", arguments, context
                    )
                )
            replayed_challenge = str(replayed.exception).split(
                "challenge_receipt_sha256=", 1
            )[1].split()[0]
            self.assertEqual(replayed_challenge, challenge)
            state = transport._load_state(SHARED_SCOPE)
            self.assertEqual(len(state["verified_receipts"]), 1)
            self.assertEqual(len(state["pending_challenges"]), 1)
            pending = state["pending_challenges"][0]
            self.assertEqual(pending["receipt_sha256"], challenge)
            self.assertEqual(pending["tool_name"], "other-write")
            self.assertEqual(pending["arguments_sha256"], arguments_sha256)

            transport.acknowledge(
                client_scope=SHARED_SCOPE,
                challenge_receipt_sha256=challenge,
                runtime_binding=BINDING,
            )
            other_result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "other-write", arguments, context
                )
            )
            state = transport._load_state(SHARED_SCOPE)
            self.assertEqual(len(state["verified_receipts"]), 1)
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool("write", arguments, context)
            )
        self.assertTrue(other_result["called"])
        self.assertTrue(result["called"])

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

    def test_missing_connector_session_identity_fails_closed_before_consumption(
        self,
    ) -> None:
        import grabowski_mcp as live_base

        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = (
            live_base._transport_roundtrip_client_scope
        )
        operator.mcp._tool_manager.get_tool = lambda _name: self.mutating_tool()
        operator._configure_http_runtime()
        context = types.SimpleNamespace(client_id=None)
        with mock.patch.object(
            operator.grabowski_transport_roundtrip, "consume_verified"
        ) as consume_verified, mock.patch.object(
            operator.grabowski_transport_roundtrip, "begin"
        ) as begin:
            with self.assertRaisesRegex(
                RuntimeError, "connector session identity is unavailable"
            ):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}, context))
        consume_verified.assert_not_called()
        begin.assert_not_called()

    def test_runtime_scope_binds_protocol_session_identity(self) -> None:
        import grabowski_mcp as live_base

        context = types.SimpleNamespace(
            client_id="mcp-client-1",
            session_id="protocol-session-abc",
        )
        scope = live_base._transport_roundtrip_client_scope(context)
        expected = roundtrip.derive_connector_session_scope(
            client_id="mcp-client-1",
            connector_session_id="protocol-session-abc",
            server_instance_id=live_base._TRANSPORT_SERVER_INSTANCE_ID,
        )
        self.assertEqual(scope, expected)
        self.assertEqual(scope["kind"], "connector_session")

    def test_runtime_scope_reads_mcp_session_id_header(self) -> None:
        import grabowski_mcp as live_base

        request = types.SimpleNamespace(
            headers={"mcp-session-id": "header-session-xyz"}
        )
        request_context = types.SimpleNamespace(request=request)

        class ContextWithoutSessionId:
            client_id = None

            def __init__(self) -> None:
                self.request_context = request_context

        scope = live_base._transport_roundtrip_client_scope(ContextWithoutSessionId())
        expected = roundtrip.derive_connector_session_scope(
            client_id=None,
            connector_session_id="header-session-xyz",
            server_instance_id=live_base._TRANSPORT_SERVER_INSTANCE_ID,
        )
        self.assertEqual(scope, expected)

    def test_read_only_status_without_live_session_reports_unavailable(self) -> None:
        import grabowski_mcp as live_base

        status = live_base._transport_roundtrip_status(None)
        self.assertEqual(status["state"], "unavailable")
        self.assertFalse(status["mutation_gate_open"])


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


class ConnectorSessionIsolationBoundaryTests(unittest.TestCase):
    """Two connector sessions remain strictly isolated.

    Identical target arguments never admit a foreign session. Admission is
    at most once, consumption receipts are distinct, and a failed effect leaves
    no reusable proof.
    """

    INTENT_ARGUMENTS = {"path": "/tmp/session-target"}

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
        self.owner_scope = META_SCOPE
        self.foreign_scope = OTHER_SCOPE

    def bind(
        self, arguments: dict[str, object], *, scope: dict[str, str]
    ) -> None:
        begun = roundtrip.begin(
            client_scope=scope,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": roundtrip.canonical_arguments_sha256(arguments),
            },
        )
        roundtrip.acknowledge(
            client_scope=scope,
            challenge_receipt_sha256=begun["challenge_receipt_sha256"],
            runtime_binding=BINDING,
        )

    def consume(
        self, arguments: dict[str, object], *, scope: dict[str, str]
    ) -> dict[str, object]:
        return roundtrip.consume_verified(
            client_scope=scope,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=roundtrip.canonical_arguments_sha256(arguments),
        )

    def test_foreign_session_cannot_consume_owner_verification(self) -> None:
        self.bind(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            self.consume(self.INTENT_ARGUMENTS, scope=self.foreign_scope)
        consumed = self.consume(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        self.assertEqual(consumed["state"], "consumed")
        self.assertIn(
            "that identical target arguments alone admit a mutation",
            consumed["does_not_establish"],
        )

    def test_foreign_session_cannot_ack_owner_challenge(self) -> None:
        begun = roundtrip.begin(
            client_scope=self.owner_scope,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": roundtrip.canonical_arguments_sha256(
                    self.INTENT_ARGUMENTS
                ),
            },
        )
        with self.assertRaisesRegex(roundtrip.TransportRoundtripError, "missing"):
            roundtrip.acknowledge(
                client_scope=self.foreign_scope,
                challenge_receipt_sha256=begun["challenge_receipt_sha256"],
                runtime_binding=BINDING,
            )

    def test_second_consume_of_one_intent_is_refused(self) -> None:
        self.bind(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        self.consume(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            self.consume(self.INTENT_ARGUMENTS, scope=self.owner_scope)

    def test_each_admission_carries_a_distinct_consumption_receipt(self) -> None:
        self.bind(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        first = self.consume(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        self.bind(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        second = self.consume(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        self.assertNotEqual(
            first["consumption_receipt_sha256"],
            second["consumption_receipt_sha256"],
        )
        self.assertNotEqual(
            first["verification_receipt_sha256"],
            second["verification_receipt_sha256"],
        )

    def test_a_failed_effect_leaves_no_reusable_proof(self) -> None:
        """Admission is consumed before the effect, so failure cannot replay."""
        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = (
            lambda context: self.owner_scope
        )

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

        self.bind(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        with mock.patch.object(
            operator.grabowski_transport_roundtrip, "STATE_ROOT", self.root
        ), mock.patch.object(
            operator.grabowski_transport_roundtrip, "LOCK_PATH", self.root / ".lock"
        ):
            with self.assertRaisesRegex(RuntimeError, "effect failed after admission"):
                asyncio.run(
                    gated(
                        "write",
                        dict(self.INTENT_ARGUMENTS),
                        types.SimpleNamespace(
                            client_id="owner", session_id="session-owner"
                        ),
                    )
                )
            with self.assertRaises(roundtrip.TransportRoundtripRequired):
                self.consume(self.INTENT_ARGUMENTS, scope=self.owner_scope)
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)


class DualConnectorSessionHarnessTests(unittest.TestCase):
    """Revision-bound two-client harness without a live ChatGPT connector.

    Two logical connector sessions complete begin/ack/mutation through the real
    transport engine and the central gate. Cross-session theft is refused.
    """

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
        self.client_a = roundtrip.derive_connector_session_scope(
            client_id="client-a",
            connector_session_id="session-a",
            server_instance_id="harness-server",
        )
        self.client_b = roundtrip.derive_connector_session_scope(
            client_id="client-b",
            connector_session_id="session-b",
            server_instance_id="harness-server",
        )
        self.arguments = {"path": "/tmp/dual-client", "content": "proof"}

    def handshake(
        self, transport: object, scope: dict[str, str]
    ) -> dict[str, object]:
        # Use wall-clock time so the central gate (which does not freeze time)
        # still sees a current verification.
        begun = transport.begin(
            client_scope=scope,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": transport.canonical_arguments_sha256(
                    self.arguments
                ),
            },
        )
        return transport.acknowledge(
            client_scope=scope,
            challenge_receipt_sha256=begun["challenge_receipt_sha256"],
            runtime_binding=BINDING,
        )

    def test_two_clients_complete_isolated_three_call_roundtrips(self) -> None:
        operator = _load_operator_module()
        transport = operator.grabowski_transport_roundtrip
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        scopes = {"session-a": self.client_a, "session-b": self.client_b}
        operator.base._transport_roundtrip_client_scope = (
            lambda context: scopes[str(getattr(context, "session_id"))]
        )
        calls: list[str] = []

        async def effect(name: str, arguments: dict[str, object], context: object):
            del arguments, context
            calls.append(str(name))
            return {"called": True, "name": name}

        operator.mcp._tool_manager.call_tool = effect
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        gated = operator.mcp._tool_manager.call_tool

        with mock.patch.object(
            transport, "STATE_ROOT", self.root
        ), mock.patch.object(
            transport, "LOCK_PATH", self.root / ".lock"
        ):
            ack_a = self.handshake(transport, self.client_a)
            ack_b = self.handshake(transport, self.client_b)
            self.assertTrue(ack_a["mutation_gate_open"])
            self.assertTrue(ack_b["mutation_gate_open"])
            self.assertNotEqual(
                ack_a["client_scope_sha256"], ack_b["client_scope_sha256"]
            )
            self.assertNotEqual(
                ack_a["verification_receipt_sha256"],
                ack_b["verification_receipt_sha256"],
            )
            # Sanity: owner scope still has an unconsumed verification.
            status_a = transport.status(
                client_scope=self.client_a, runtime_binding=BINDING
            )
            self.assertTrue(status_a["mutation_gate_open"])
            self.assertEqual(status_a["verified_receipt_count"], 1)

            result_a = asyncio.run(
                gated(
                    "write",
                    dict(self.arguments),
                    types.SimpleNamespace(client_id="client-a", session_id="session-a"),
                )
            )
            # Client B still holds its own verification after A mutated.
            result_b = asyncio.run(
                gated(
                    "write",
                    dict(self.arguments),
                    types.SimpleNamespace(client_id="client-b", session_id="session-b"),
                )
            )
            # Replaying A without a new handshake fails closed before effect.
            with self.assertRaisesRegex(
                RuntimeError, "fresh intent-bound transport verification required"
            ):
                asyncio.run(
                    gated(
                        "write",
                        dict(self.arguments),
                        types.SimpleNamespace(
                            client_id="client-a", session_id="session-a"
                        ),
                    )
                )

        self.assertTrue(result_a["called"])
        self.assertTrue(result_b["called"])
        self.assertEqual(calls, ["write", "write"])


if __name__ == "__main__":
    unittest.main()

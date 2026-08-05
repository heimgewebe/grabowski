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
        self.assertEqual(contract["version"], "1.1")
        self.assertIn("exact-target-bound", contract["acceptance_ids"])
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

    def test_stateless_shared_scope_admits_two_independent_handshakes(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        operator = self.configured_operator()
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

            context = types.SimpleNamespace(client_id=None)
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
    """The declared boundary of a shared, unlabeled storage partition.

    shared_unlabeled is a storage partition, never a caller identity. Two
    unlabeled callers of the same exact intent are indistinguishable by
    construction. What the contract must still guarantee for them is
    at-most-once admission of the effect, a distinct consumption receipt per
    admission, and no reusable proof once an admission was spent.
    """

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

    def bind(self, arguments: dict[str, object]) -> None:
        begun = roundtrip.begin(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            mutation_intent={
                "tool_name": "write",
                "arguments_sha256": roundtrip.canonical_arguments_sha256(arguments),
            },
        )
        roundtrip.acknowledge(
            client_scope=SHARED_SCOPE,
            challenge_receipt_sha256=begun["challenge_receipt_sha256"],
            runtime_binding=BINDING,
        )

    def consume(self, arguments: dict[str, object]) -> dict[str, object]:
        return roundtrip.consume_verified(
            client_scope=SHARED_SCOPE,
            runtime_binding=BINDING,
            tool_name="write",
            arguments_sha256=roundtrip.canonical_arguments_sha256(arguments),
        )

    def test_shared_scope_is_declared_a_partition_not_an_identity(self) -> None:
        self.bind(self.INTENT_ARGUMENTS)
        consumed = self.consume(self.INTENT_ARGUMENTS)
        self.assertIn(
            "caller identity: shared_unlabeled is a shared storage partition, "
            "not an identity",
            consumed["does_not_establish"],
        )
        status = roundtrip.status(
            client_scope=SHARED_SCOPE, runtime_binding=BINDING
        )
        self.assertIn(
            "that two unlabeled callers of the same exact intent are "
            "distinguishable",
            status["does_not_establish"],
        )

    def test_second_unlabeled_caller_of_one_intent_is_refused(self) -> None:
        """One admission per handshake, even though the callers are alike."""
        self.bind(self.INTENT_ARGUMENTS)
        self.consume(self.INTENT_ARGUMENTS)
        with self.assertRaises(roundtrip.TransportRoundtripRequired):
            self.consume(self.INTENT_ARGUMENTS)

    def test_each_admission_carries_a_distinct_consumption_receipt(self) -> None:
        self.bind(self.INTENT_ARGUMENTS)
        first = self.consume(self.INTENT_ARGUMENTS)
        self.bind(self.INTENT_ARGUMENTS)
        second = self.consume(self.INTENT_ARGUMENTS)
        self.assertNotEqual(
            first["consumption_receipt_sha256"],
            second["consumption_receipt_sha256"],
        )
        self.assertNotEqual(
            first["verification_receipt_sha256"],
            second["verification_receipt_sha256"],
        )

    def test_a_failed_effect_leaves_no_reusable_proof(self) -> None:
        """Admission is consumed before the effect, so failure cannot replay.

        This is the ambiguity contract: a lost response and a failed effect are
        indistinguishable to the gate, and both must leave the caller without a
        spendable proof.
        """
        operator = _load_operator_module()
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = lambda context: SHARED_SCOPE

        async def exploding_effect(*_args: object, **_kwargs: object):
            raise RuntimeError("effect failed after admission")

        # Replace the underlying effect before the gate wraps it, so the
        # admission is genuinely spent and only then does the effect fail.
        operator.mcp._tool_manager.call_tool = exploding_effect
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        gated = operator.mcp._tool_manager.call_tool

        self.bind(self.INTENT_ARGUMENTS)
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
                        types.SimpleNamespace(client_id=None),
                    )
                )
            # The verification was spent before the effect ran, so no proof
            # survives the failure.
            with self.assertRaises(roundtrip.TransportRoundtripRequired):
                self.consume(self.INTENT_ARGUMENTS)
        self.assertEqual(operator._deployment_admission_active_tool_calls(), 0)


if __name__ == "__main__":
    unittest.main()

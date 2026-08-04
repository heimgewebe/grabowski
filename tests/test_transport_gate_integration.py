from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import grabowski_grips as grips
import grabowski_transport_roundtrip as roundtrip
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
        return {
            "action": action,
            "_server_transport_client_scope": META_SCOPE,
            "_server_transport_runtime_binding": BINDING,
            **extra,
        }

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
            with self.assertRaisesRegex(RuntimeError, "handshake required"):
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
                )["challenge_receipt_sha256"]
                for _ in range(2)
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
                RuntimeError, "fresh single-use transport verification"
            ):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "write", {"sequence": 3}, context
                    )
                )

    def test_bound_shared_verification_cannot_be_stolen_by_other_tool(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        operator = self.configured_operator()
        transport = operator.grabowski_transport_roundtrip
        context = types.SimpleNamespace(client_id=None)
        arguments = {"sequence": 1}
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
        ):
            begin = transport.begin(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "write",
                    "arguments_sha256": transport.canonical_arguments_sha256(arguments),
                },
            )
            transport.acknowledge(
                client_scope=SHARED_SCOPE,
                challenge_receipt_sha256=begin["challenge_receipt_sha256"],
                runtime_binding=BINDING,
            )
            with self.assertRaisesRegex(RuntimeError, "bound to a different mutation"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "other-write", arguments, context
                    )
                )
            status = transport.status(
                client_scope=SHARED_SCOPE,
                runtime_binding=BINDING,
            )
            self.assertEqual(status["verified_receipt_count"], 1)
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool("write", arguments, context)
            )
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
            with self.assertRaisesRegex(RuntimeError, "handshake required"):
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
            return_value={"state": "consumed"},
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


if __name__ == "__main__":
    unittest.main()

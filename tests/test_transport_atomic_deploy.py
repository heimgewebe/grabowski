from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import grabowski_transport_assertion as assertion
import grabowski_transport_roundtrip as roundtrip
from tests.test_operator_v2_runtime import _load_grabowski_mcp
from tests.test_operator_contract import _load_operator_module


BINDING = {
    "release_id": "release-1",
    "repo_head": "a" * 40,
    "registered_names_sha256": "b" * 64,
    "agent_instructions_sha256": "c" * 64,
}
SCOPE = {"kind": "connector_capability", "label": "fixture-connector"}


class AtomicTransportDeployTests(unittest.TestCase):
    @staticmethod
    def mutating_tool() -> object:
        return types.SimpleNamespace(
            is_async=True,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )

    @staticmethod
    def signed_headers(base: object) -> dict[str, str]:
        return {
            base._TRANSPORT_INGRESS_VERSION_HEADER: assertion.ASSERTION_VERSION,
            base._TRANSPORT_REQUEST_ID_HEADER: "fixture-request",
            base._TRANSPORT_REQUEST_TIMESTAMP_HEADER: "100",
            base._TRANSPORT_REQUEST_AUDIENCE_HEADER: "fixture-audience",
            base._TRANSPORT_REQUEST_BODY_SHA256_HEADER: "1" * 64,
            base._TRANSPORT_RUNTIME_BINDING_SHA256_HEADER: (
                assertion.runtime_binding_sha256(BINDING)
            ),
            base._TRANSPORT_REQUEST_MAC_HEADER: "2" * 64,
        }

    def signed_context_patches(self, base: object):
        headers = self.signed_headers(base)
        return (
            mock.patch.object(
                base,
                "_transport_context_header",
                side_effect=lambda _ctx, name: headers.get(name),
            ),
            mock.patch.object(
                base,
                "_transport_context_connector_capability",
                return_value=b"fixture-secret",
            ),
            mock.patch.object(
                base,
                "_transport_connector_capability_scope",
                return_value=SCOPE,
            ),
            mock.patch.object(
                base.grabowski_transport_assertion,
                "consume_assertion",
                side_effect=assertion.TransportAssertionReplay(
                    "signed one-call transport request was already consumed"
                ),
            ),
        )

    def test_direct_signed_replay_is_not_suppressed_without_atomic_capability(self) -> None:
        base = _load_grabowski_mcp()
        arguments = {"expected_head": "d" * 40, "delay_seconds": 10}
        digest = roundtrip.canonical_arguments_sha256(arguments)
        context = types.SimpleNamespace(client_id="fixture-client")
        patches = self.signed_context_patches(base)
        with patches[0], patches[1], patches[2], patches[3]:
            with self.assertRaises(assertion.TransportAssertionReplay):
                base._transport_signed_one_call_evidence(
                    context,
                    tool_name="grabowski_runtime_deploy_schedule",
                    arguments_sha256=digest,
                    runtime_binding=BINDING,
                )

    def test_atomic_dispatch_consumes_reserved_roundtrip_after_signed_replay(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        base = _load_grabowski_mcp()
        transport = base.grabowski_transport_roundtrip
        arguments = {"expected_head": "d" * 40, "delay_seconds": 10}
        digest = transport.canonical_arguments_sha256(arguments)
        context = types.SimpleNamespace(client_id="fixture-client")

        async def target_call(name, target_arguments, target_context):
            signed = base._transport_signed_one_call_evidence(
                target_context,
                tool_name=name,
                arguments_sha256=transport.canonical_arguments_sha256(target_arguments),
                runtime_binding=BINDING,
            )
            self.assertIsNone(signed)
            consumed = transport.consume_verified(
                client_scope=SCOPE,
                runtime_binding=BINDING,
                tool_name=name,
                arguments_sha256=digest,
            )
            return {
                "called": True,
                "consumption_receipt_sha256": consumed[
                    "consumption_receipt_sha256"
                ],
            }

        base.mcp._tool_manager = types.SimpleNamespace(
            get_tool=lambda _name: self.mutating_tool(),
            call_tool=target_call,
        )
        patches = self.signed_context_patches(base)
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
            patches[0],
            patches[1],
            patches[2],
            patches[3],
        ):
            begun = transport.begin(
                client_scope=SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "grabowski_runtime_deploy_schedule",
                    "arguments_sha256": digest,
                },
            )
            challenge = begun["challenge_receipt_sha256"]
            transport.reserve_execution(
                client_scope=SCOPE,
                challenge_receipt_sha256=challenge,
                runtime_binding=BINDING,
                tool_name="grabowski_runtime_deploy_schedule",
                arguments_sha256=digest,
            )
            result = asyncio.run(
                base._dispatch_atomic_transport_target(
                    "grabowski_runtime_deploy_schedule",
                    arguments,
                    challenge,
                    context,
                )
            )

        self.assertIsNone(result["target_error"])
        self.assertTrue(result["target_result"]["called"])
        self.assertIsNotNone(result["execution"]["consumption_receipt_sha256"])

    def test_atomic_capability_without_reserved_verification_grants_no_authority(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        base = _load_grabowski_mcp()
        transport = base.grabowski_transport_roundtrip
        arguments = {"expected_head": "d" * 40, "delay_seconds": 10}
        digest = transport.canonical_arguments_sha256(arguments)
        context = types.SimpleNamespace(client_id="fixture-client")

        async def target_call(name, target_arguments, target_context):
            signed = base._transport_signed_one_call_evidence(
                target_context,
                tool_name=name,
                arguments_sha256=transport.canonical_arguments_sha256(target_arguments),
                runtime_binding=BINDING,
            )
            self.assertIsNone(signed)
            return transport.consume_verified(
                client_scope=SCOPE,
                runtime_binding=BINDING,
                tool_name=name,
                arguments_sha256=digest,
            )

        base.mcp._tool_manager = types.SimpleNamespace(
            get_tool=lambda _name: self.mutating_tool(),
            call_tool=target_call,
        )
        patches = self.signed_context_patches(base)
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
            patches[0],
            patches[1],
            patches[2],
            patches[3],
        ):
            begun = transport.begin(
                client_scope=SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "grabowski_runtime_deploy_schedule",
                    "arguments_sha256": digest,
                },
            )
            challenge = begun["challenge_receipt_sha256"]
            result = asyncio.run(
                base._dispatch_atomic_transport_target(
                    "grabowski_runtime_deploy_schedule",
                    arguments,
                    challenge,
                    context,
                )
            )

        self.assertEqual(result["target_error"]["type"], "TransportRoundtripRequired")
        self.assertIsNone(result["execution"]["consumption_receipt_sha256"])


    def test_operator_gate_consumes_reserved_roundtrip_inside_atomic_context(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "state"
        base = _load_grabowski_mcp()
        operator = _load_operator_module()
        transport = operator.grabowski_transport_roundtrip
        arguments = {"expected_head": "d" * 40, "delay_seconds": 10}
        digest = transport.canonical_arguments_sha256(arguments)
        context = types.SimpleNamespace(client_id="fixture-client")
        tool = self.mutating_tool()
        operator.base._transport_signed_one_call_evidence = (
            base._transport_signed_one_call_evidence
        )
        operator.base._transport_roundtrip_runtime_binding = lambda: BINDING
        operator.base._transport_roundtrip_client_scope = lambda _ctx: SCOPE
        patches = self.signed_context_patches(base)
        with (
            mock.patch.object(transport, "STATE_ROOT", root),
            mock.patch.object(transport, "LOCK_PATH", root / ".lock"),
            mock.patch.object(operator, "_require_current_serving_process"),
            patches[0],
            patches[1],
            patches[2],
            patches[3],
        ):
            begun = transport.begin(
                client_scope=SCOPE,
                runtime_binding=BINDING,
                mutation_intent={
                    "tool_name": "grabowski_runtime_deploy_schedule",
                    "arguments_sha256": digest,
                },
            )
            challenge = begun["challenge_receipt_sha256"]
            transport.reserve_execution(
                client_scope=SCOPE,
                challenge_receipt_sha256=challenge,
                runtime_binding=BINDING,
                tool_name="grabowski_runtime_deploy_schedule",
                arguments_sha256=digest,
            )
            with transport.execution_capability(challenge):
                evidence = operator._require_transport_roundtrip_for_tool(
                    tool_name="grabowski_runtime_deploy_schedule",
                    arguments=arguments,
                    context=context,
                    tool=tool,
                )

        self.assertEqual(evidence["state"], "consumed")
        self.assertIsNotNone(evidence["consumption_receipt_sha256"])
        self.assertNotIn("signed_one_call_replay_recovery", evidence)


if __name__ == "__main__":
    unittest.main()

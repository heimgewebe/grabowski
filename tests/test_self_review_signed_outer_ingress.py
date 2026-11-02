"""A real signed ingress request must be consumed once across the MCP gate and reviewer.

The outer FastMCP dispatcher authenticates the exact request before the inner
first-party handler runs in a worker. Reconsumption inside the handler is a
durable replay, not a second authentication. The server-owned scoped handoff
must retain the original MAC-bound principal without accepting caller JSON.
"""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_transport_one_call as fixture

base = fixture.base
operator = fixture.operator
review = fixture.review
assertion = fixture.assertion
ingress = fixture.ingress


class SignedOuterFirstPartyIngressTests(unittest.TestCase):
    def test_outer_consumption_is_reused_only_for_exact_authenticated_issuer(self):
        name = review.FIRST_PARTY_TOOL_START
        arguments = {
            "review_batch_id": "d" * 32,
            "reason": "Inspect authentic immutable Git source",
            "user_intent": "Review the exact source revision",
        }
        token = "C" * 43
        body = json.dumps({
            "jsonrpc": "2.0", "id": 199, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
        signed = ingress.signed_tool_headers(
            token=token, body=body, session_id="primary-review-session",
            runtime_binding_sha256=fixture._runtime_sha256(),
        )
        headers = {
            base._TRANSPORT_CONNECTOR_CAPABILITY_HEADER: token,
            base._TRANSPORT_MCP_SESSION_ID_HEADER: "primary-review-session",
            base._TRANSPORT_INGRESS_VERSION_HEADER: assertion.ASSERTION_VERSION,
            base._TRANSPORT_REQUEST_ID_HEADER: signed[ingress.REQUEST_ID_HEADER],
            base._TRANSPORT_REQUEST_TIMESTAMP_HEADER:
                signed[ingress.REQUEST_TIMESTAMP_HEADER],
            base._TRANSPORT_REQUEST_AUDIENCE_HEADER:
                signed[ingress.REQUEST_AUDIENCE_HEADER],
            base._TRANSPORT_REQUEST_BODY_SHA256_HEADER:
                signed[ingress.REQUEST_BODY_SHA256_HEADER],
            base._TRANSPORT_RUNTIME_BINDING_SHA256_HEADER:
                signed[ingress.RUNTIME_BINDING_SHA256_HEADER],
            base._TRANSPORT_REQUEST_MAC_HEADER: signed[ingress.REQUEST_MAC_HEADER],
        }
        context = fixture._ctx(headers)
        tool = SimpleNamespace(annotations=SimpleNamespace(readOnlyHint=False))
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            connectors = parent / "connectors"
            connectors.mkdir(mode=0o700)
            primary = connectors / "primary.token"
            primary.write_text(token, encoding="ascii")
            primary.chmod(0o600)
            state = parent / "replay"
            with (
                mock.patch.object(base, "_TRANSPORT_CONNECTOR_IDENTITY_ROOT", connectors),
                mock.patch.object(base, "_transport_roundtrip_runtime_binding",
                                  return_value=fixture.BINDING),
                mock.patch.object(base, "_transport_registered_tool_names",
                                  return_value={name}),
                mock.patch.object(operator, "_require_current_serving_process",
                                  return_value=None),
                mock.patch.object(assertion, "STATE_ROOT", state),
                mock.patch.object(assertion, "LOCK_PATH", state / ".lock"),
            ):
                consumed = operator._require_transport_roundtrip_for_tool(
                    tool_name=name, arguments=arguments,
                    context=context, tool=tool,
                )
                self.assertEqual(consumed["state"], "consumed")
                self.assertEqual(consumed["transport_mode"], "signed-one-call-v1")
                self.assertEqual(consumed["tool_name"], name)
                with base._first_party_preconsumed_transport(consumed):
                    issuer = base._authenticated_self_review_issuer(
                        context, tool_name=name, arguments=arguments,
                    )
                    self.assertEqual(issuer["connector_id"], "primary")
                    self.assertEqual(issuer["request_id"], consumed["request_id"])
                    self.assertEqual(
                        issuer["consumption_receipt_sha256"],
                        consumed["consumption_receipt_sha256"],
                    )
                    with self.assertRaisesRegex(RuntimeError, "handoff"):
                        base._authenticated_self_review_issuer(
                            context, tool_name=name,
                            arguments={**arguments, "reason": "tampered"},
                        )
                    with self.assertRaisesRegex(RuntimeError, "handoff"):
                        base._authenticated_self_review_issuer(
                            context, tool_name=review.FIRST_PARTY_TOOL_READ,
                            arguments=arguments,
                        )
                # An old signed call cannot be independently reconsumed after
                # the scoped handoff expires, even though the token is valid.
                with self.assertRaises(assertion.TransportAssertionReplay):
                    base._authenticated_self_review_issuer(
                        context, tool_name=name, arguments=arguments,
                    )


    def test_operator_sync_worker_receives_only_the_one_outer_consumed_proof(self):
        # This exercises the real FastMCP gate's sync worker handoff, rather
        # than only the isolated issuer function tested above.
        manager = operator.mcp._tool_manager
        original_call = manager.call_tool
        original_get = manager.get_tool
        evidence = {
            "state": "consumed", "transport_mode": "signed-one-call-v1",
            "tool_name": review.FIRST_PARTY_TOOL_START,
            "request_id": "a" * 32,
        }
        async def domain_call(_name, _arguments, _context):
            return base._FIRST_PARTY_CONSUMED_SIGNED_EVIDENCE.get()
        manager.call_tool = domain_call
        manager.get_tool = lambda _name: SimpleNamespace(
            is_async=False, context_kwarg=None,
            annotations=SimpleNamespace(readOnlyHint=False),
        )
        try:
            with (
                mock.patch.object(operator, "_DEPLOYMENT_ADMISSION_GATE_INSTALLED", False),
                mock.patch.object(base, "_transport_authorize_connector_tool",
                                  return_value={"connector_id": "primary"}),
                mock.patch.object(operator, "_require_transport_roundtrip_for_tool",
                                  return_value=evidence),
                mock.patch.object(operator.grabowski_effect_interceptor,
                                  "fence_enforcement_required", return_value=False),
                mock.patch.object(operator.grabowski_effect_interceptor,
                                  "admit_mutation", return_value=None),
            ):
                operator._install_deployment_admission_gate()
                received = operator.asyncio.run(
                    manager.call_tool(
                        review.FIRST_PARTY_TOOL_START,
                        {"review_batch_id": "d" * 32}, fixture._ctx({}),
                    )
                )
                self.assertEqual(received, evidence)
                # No first-party issuer leaks to an unrelated tool call.
                received_other = operator.asyncio.run(
                    manager.call_tool("write", {}, fixture._ctx({}))
                )
                self.assertIsNone(received_other)
            self.assertIsNone(base._FIRST_PARTY_CONSUMED_SIGNED_EVIDENCE.get())
        finally:
            manager.call_tool = original_call
            manager.get_tool = original_get


if __name__ == "__main__":
    unittest.main()
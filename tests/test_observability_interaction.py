from __future__ import annotations

import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp.server.fastmcp import FastMCP
from mcp.server.lowlevel.server import request_ctx
from mcp.shared.context import RequestContext
from mcp.types import CallToolRequest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from posthog.mcp import instrument
from posthog.mcp.types import MCPAnalyticsOptions

import grabowski_flowlines as flowlines
import grabowski_operator as operator


class _CapturingPostHog:
    def __init__(self, *, fail_capture: bool = False) -> None:
        self.events: list[dict[str, object]] = []
        self.fail_capture = fail_capture
        self.library_identity: tuple[str, str] | None = None
        self.shutdown_calls = 0

    def _set_library_identity(self, name: str, version: str) -> None:
        self.library_identity = (name, version)

    def capture(
        self,
        event: str,
        *,
        distinct_id: str,
        properties: dict[str, object],
        timestamp=None,
        uuid=None,
    ) -> None:
        del uuid
        if self.fail_capture:
            raise RuntimeError("posthog fixture transport failure")
        self.events.append(
            {
                "event": event,
                "distinct_id": distinct_id,
                "properties": dict(properties),
                "timestamp": timestamp,
            }
        )

    def shutdown(self) -> None:
        self.shutdown_calls += 1


class _FailingTracer:
    def start_as_current_span(self, *args, **kwargs):
        del args, kwargs
        raise RuntimeError("flowlines fixture span setup failure")


class ObservabilityInteractionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider(sampler=ALWAYS_ON)
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("tests.observability-interaction")
        self._prior_gate_installed = operator._DEPLOYMENT_ADMISSION_GATE_INSTALLED

    def tearDown(self) -> None:
        operator._DEPLOYMENT_ADMISSION_GATE_INSTALLED = self._prior_gate_installed
        self.provider.shutdown()

    @staticmethod
    def _posthog_options() -> MCPAnalyticsOptions:
        return MCPAnalyticsOptions(
            report_missing=False,
            enable_conversation_id=False,
            enable_exception_autocapture=False,
            context=False,
            capture_model=False,
            collect_feedback=False,
            before_send=operator._posthog_metadata_only_before_send,
        )

    @staticmethod
    def _meta() -> dict[str, str]:
        return {
            "session.id": "combined-session",
            "user.id": "combined-user",
        }

    def _server(self, tracer):
        calls: list[dict[str, str]] = []
        mcp = FastMCP("grabowski-combined-test", instructions="fixture")

        @mcp.tool(name="combined_observe", annotations=operator.READ_ONLY)
        def combined_observe(
            authorization: str,
            reason: str,
        ) -> dict[str, str]:
            calls.append(
                {
                    "authorization": authorization,
                    "reason": reason,
                }
            )
            return {"payload": "private-result-marker"}

        flowlines.configure_flowlines_observability(
            mcp,
            operator.READ_ONLY,
            tracer=tracer,
        )
        return mcp, calls

    @staticmethod
    async def _call(mcp: FastMCP, *, secret: str, user_intent: str):
        request = CallToolRequest(
            params={
                "name": "combined_observe",
                "arguments": {
                    "authorization": secret,
                    "reason": "domain-owned reason",
                    "user_intent": user_intent,
                },
                "_meta": ObservabilityInteractionTests._meta(),
            }
        )
        context = RequestContext(
            request_id=77,
            meta=request.params.meta,
            session=SimpleNamespace(),
            lifespan_context={},
            request=SimpleNamespace(headers={"mcp-session-id": "transport-session"}),
        )
        token = request_ctx.set(context)
        try:
            handler = mcp._mcp_server.request_handlers[CallToolRequest]
            return await handler(request)
        finally:
            request_ctx.reset(token)

    def _install_posthog_then_http_gate(
        self,
        mcp: FastMCP,
        client: _CapturingPostHog,
    ):
        analytics = instrument(mcp, client, self._posthog_options())
        with mock.patch.object(operator, "mcp", mcp):
            operator._configure_http_runtime()
        self.assertTrue(
            getattr(
                mcp._tool_manager.call_tool,
                "_grabowski_deployment_admission_gate",
                False,
            )
        )
        return analytics

    async def test_real_wrapper_stack_executes_once_and_separates_privacy_domains(self) -> None:
        secret = "Bearer private-combined-secret"
        private_intent = "private combined user intent"
        mcp, calls = self._server(self.tracer)
        client = _CapturingPostHog()
        self._install_posthog_then_http_gate(mcp, client)

        result = await self._call(mcp, secret=secret, user_intent=private_intent)

        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"payload": "private-result-marker"})
        self.assertEqual(
            calls,
            [{"authorization": secret, "reason": "domain-owned reason"}],
        )

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual(span.attributes["gen_ai.tool.name"], "combined_observe")
        self.assertEqual(
            span.attributes["gen_ai.tool.call.reason"],
            "domain-owned reason",
        )
        self.assertEqual(
            span.attributes["session.user_intent"],
            private_intent,
        )
        flowline_arguments = json.loads(
            span.attributes["gen_ai.tool.call.arguments"]
        )
        self.assertEqual(flowline_arguments["authorization"], "<redacted>")
        self.assertEqual(flowline_arguments["reason"], "domain-owned reason")
        self.assertEqual(flowline_arguments["user_intent"], private_intent)

        self.assertEqual(len(client.events), 1)
        event = client.events[0]
        self.assertEqual(event["event"], "$mcp_tool_call")
        self.assertEqual(event["distinct_id"], operator.POSTHOG_DISTINCT_ID)
        properties = event["properties"]
        assert isinstance(properties, dict)
        self.assertEqual(properties["$mcp_tool_name"], "combined_observe")
        self.assertFalse(properties["$mcp_is_error"])
        self.assertTrue(properties["$geoip_disable"])
        self.assertFalse(properties["$process_person_profile"])
        self.assertTrue(
            set(properties).issubset(
                set(operator.POSTHOG_METADATA_PROPERTIES)
                | {"$geoip_disable", "$process_person_profile"}
            )
        )
        encoded_event = repr(event)
        for forbidden in (
            secret,
            private_intent,
            "domain-owned reason",
            "private-result-marker",
            "$mcp_parameters",
            "$mcp_response",
            "$mcp_intent",
            "$mcp_error_message",
        ):
            self.assertNotIn(forbidden, encoded_event)

    async def test_posthog_capture_failure_does_not_break_flowlines_or_domain(self) -> None:
        mcp, calls = self._server(self.tracer)
        client = _CapturingPostHog(fail_capture=True)
        self._install_posthog_then_http_gate(mcp, client)

        result = await self._call(
            mcp,
            secret="Bearer posthog-failure-secret",
            user_intent="verify PostHog failure isolation",
        )

        self.assertFalse(result.root.isError)
        self.assertEqual(len(calls), 1)
        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        self.assertEqual(spans[0].status.status_code.name, "OK")
        self.assertEqual(client.events, [])

    async def test_flowlines_span_setup_failure_does_not_break_posthog_or_domain(self) -> None:
        mcp, calls = self._server(_FailingTracer())
        client = _CapturingPostHog()
        self._install_posthog_then_http_gate(mcp, client)

        result = await self._call(
            mcp,
            secret="Bearer flowlines-failure-secret",
            user_intent="verify Flowlines failure isolation",
        )

        self.assertFalse(result.root.isError)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.exporter.get_finished_spans(), ())
        self.assertEqual(len(client.events), 1)
        self.assertEqual(client.events[0]["event"], "$mcp_tool_call")
        self.assertEqual(
            client.events[0]["properties"]["$mcp_tool_name"],
            "combined_observe",
        )


if __name__ == "__main__":
    unittest.main()
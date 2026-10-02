from __future__ import annotations

import json
import os
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
from mcp.types import CallToolRequest, ToolAnnotations
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

import grabowski_flowlines as flowlines


READ_ONLY = ToolAnnotations(readOnlyHint=True)


class FlowlinesObservabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider(sampler=ALWAYS_ON)
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("tests.flowlines")

    def tearDown(self) -> None:
        self.provider.shutdown()

    def server(self, *, description: str = "Echo one value.", verified_resolver=None):
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="echo", description=description, annotations=READ_ONLY)
        def echo(value: str) -> dict[str, str]:
            return {"value": value}

        flowlines.configure_flowlines_observability(
            mcp,
            READ_ONLY,
            tracer=self.tracer,
            verified_identity_resolver=verified_resolver,
        )
        return mcp

    async def call(
        self,
        mcp: FastMCP,
        *,
        name: str = "echo",
        arguments: dict,
        meta: dict | None = None,
        request_id: int | str = 42,
        headers: dict[str, str] | None = None,
    ):
        req = CallToolRequest(
            params={
                "name": name,
                "arguments": arguments,
                "_meta": meta or {},
            }
        )
        context = RequestContext(
            request_id=request_id,
            meta=req.params.meta,
            session=SimpleNamespace(),
            lifespan_context={},
            request=SimpleNamespace(headers=headers or {}),
        )
        token = request_ctx.set(context)
        try:
            handler = mcp._mcp_server.request_handlers[CallToolRequest]
            return await handler(req)
        finally:
            request_ctx.reset(token)

    @staticmethod
    def meta(**extra):
        value = {
            "session.id": "session-1",
            "user.id": "user-17",
            "user.name": "Ada",
            "user.email": "ada@example.invalid",
        }
        value.update(extra)
        return value

    def test_public_schema_requires_flowlines_fields_and_report_outcome(self) -> None:
        mcp = self.server()
        echo = mcp._tool_manager.get_tool("echo")
        assert echo is not None
        self.assertIn("reason", echo.parameters["properties"])
        self.assertIn("user_intent", echo.parameters["properties"])
        self.assertTrue({"reason", "user_intent"}.issubset(set(echo.parameters["required"])))

        report = mcp._tool_manager.get_tool(flowlines.REPORT_OUTCOME_TOOL)
        assert report is not None
        self.assertTrue(report.description.startswith("REQUIRED final call in every conversation"))
        required = set(report.parameters["required"])
        self.assertTrue(
            {"reason", "user_intent", "status", "outcome_summary"}.issubset(required)
        )
        status_schema = report.parameters["properties"]["status"]
        self.assertEqual(status_schema.get("enum"), ["accomplished", "partial", "failed"])

    async def test_success_span_contains_canonical_contract_and_strips_analytics_args(self) -> None:
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Read the fixture value",
                "user_intent": "Verify Flowlines instrumentation",
            },
            meta=self.meta(),
            request_id=77,
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": "hello"})

        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 1)
        span = spans[0]
        attrs = span.attributes
        self.assertEqual(span.status.status_code.name, "OK")
        self.assertEqual(attrs["gen_ai.operation.name"], "execute_tool")
        self.assertEqual(attrs["gen_ai.tool.name"], "echo")
        self.assertEqual(attrs["mcp.method.name"], "tools/call")
        self.assertEqual(attrs["mcp.server.name"], "grabowski-test")
        self.assertEqual(attrs["mcp.request.id"], "77")
        self.assertNotEqual(attrs["gen_ai.tool.call.id"], "77")
        self.assertEqual(attrs["session.id"], "session-1")
        self.assertEqual(attrs["user.id"], "user-17")
        self.assertEqual(attrs["user.name"], "Ada")
        self.assertEqual(attrs["user.email"], "ada@example.invalid")
        self.assertEqual(attrs["gen_ai.tool.call.reason"], "Read the fixture value")
        self.assertEqual(attrs["session.user_intent"], "Verify Flowlines instrumentation")

        public_arguments = json.loads(attrs["gen_ai.tool.call.arguments"])
        self.assertEqual(public_arguments["value"], "hello")
        self.assertEqual(public_arguments["reason"], "Read the fixture value")
        self.assertNotIn("_meta", public_arguments)

        captured_result = json.loads(attrs["gen_ai.tool.call.result"])
        self.assertFalse(captured_result["isError"])
        self.assertEqual(captured_result["structuredContent"], {"value": "hello"})

        declared = json.loads(attrs["gen_ai.tool.input_schema"])
        published = mcp._tool_manager.get_tool("echo").parameters
        self.assertEqual(declared, published)
        output = json.loads(attrs["gen_ai.tool.output_schema"])
        self.assertEqual(output, mcp._tool_manager.get_tool("echo").output_schema)

    async def test_export_disabled_keeps_legacy_calls_compatible(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="echo", annotations=READ_ONLY)
        def echo(value: str) -> dict[str, str]:
            return {"value": value}

        with mock.patch.dict(
            os.environ,
            {
                "GRABOWSKI_FLOWLINES_ENABLED": "",
                "OTEL_EXPORTER_OTLP_HEADERS": "",
            },
            clear=False,
        ):
            state = flowlines.configure_flowlines_observability(mcp, READ_ONLY)

        self.assertFalse(state["export_enabled"])
        published = mcp._tool_manager.get_tool("echo").parameters
        self.assertTrue({"reason", "user_intent"}.issubset(published["required"]))

        result = await self.call(
            mcp,
            arguments={"value": "legacy"},
            meta=self.meta(),
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": "legacy"})
        self.assertEqual(self.exporter.get_finished_spans(), ())

    async def test_missing_identity_is_fail_open_but_emits_no_span(self) -> None:
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Read the fixture value",
                "user_intent": "Verify Flowlines instrumentation",
            },
            meta={"session.id": "session-1"},
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(self.exporter.get_finished_spans(), ())

    async def test_verified_identity_overrides_client_analytics_identity(self) -> None:
        mcp = self.server(
            verified_resolver=lambda _ctx: {
                "id": "verified-9",
                "name": "Verified Name",
                "email": "verified@example.invalid",
            }
        )
        await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Read the fixture value",
                "user_intent": "Verify identity precedence",
            },
            meta=self.meta(
                **{
                    "user.id": "spoofed",
                    "user.name": "Spoofed Name",
                    "user.email": "spoofed@example.invalid",
                }
            ),
        )
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(span.attributes["user.id"], "verified-9")
        self.assertEqual(span.attributes["user.name"], "Verified Name")
        self.assertEqual(span.attributes["user.email"], "verified@example.invalid")

    async def test_error_span_is_explicit_and_does_not_export_raw_exception(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="explode", annotations=READ_ONLY)
        def explode() -> dict[str, str]:
            raise RuntimeError("sensitive backend detail must not enter telemetry")

        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)
        result = await self.call(
            mcp,
            name="explode",
            arguments={
                "reason": "Exercise the error boundary",
                "user_intent": "Verify Flowlines error safety",
            },
            meta=self.meta(),
        )
        self.assertTrue(result.root.isError)
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(span.status.status_code.name, "ERROR")
        self.assertEqual(span.attributes["error.type"], "tool_error")
        captured = span.attributes["gen_ai.tool.call.result"]
        self.assertNotIn("sensitive backend detail", captured)
        self.assertEqual(
            json.loads(captured),
            {"content": [{"text": "tool_error", "type": "text"}], "isError": True},
        )

    async def test_invalid_reason_is_rejected_without_telemetry(self) -> None:
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": " ",
                "user_intent": "Verify Flowlines validation",
            },
            meta=self.meta(),
        )
        self.assertTrue(result.root.isError)
        self.assertEqual(self.exporter.get_finished_spans(), ())

    async def test_description_is_trimmed_and_capped(self) -> None:
        description = "  " + ("x" * 10_050) + "  "
        mcp = self.server(description=description)
        await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Inspect description metadata",
                "user_intent": "Verify Flowlines metadata bounds",
            },
            meta=self.meta(),
        )
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(len(span.attributes["gen_ai.tool.description"]), 10_000)
        self.assertFalse(span.attributes["gen_ai.tool.description"].startswith(" "))

    def test_oversized_declared_schema_is_omitted_whole(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "value": {"type": "string", "description": "x" * 60_000}
            },
        }
        self.assertIsNone(flowlines._schema_attribute(schema))

    async def test_sensitive_argument_keys_are_redacted_from_telemetry(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="credential_tool", annotations=READ_ONLY)
        def credential_tool(
            password: str,
            environment: dict[str, str],
            headers: dict[str, str],
            service_token: str,
            value: str,
        ) -> dict[str, str]:
            return {
                "value": value,
                "password_seen": str(bool(password)),
                "environment_seen": str(bool(environment)),
                "headers_seen": str(bool(headers)),
                "token_seen": str(bool(service_token)),
            }

        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)
        await self.call(
            mcp,
            name="credential_tool",
            arguments={
                "password": "must-not-export",
                "environment": {
                    "ARBITRARY_PROVIDER_SECRET": "must-not-export-env",
                },
                "headers": {
                    "X-Custom": "must-not-export-header",
                },
                "service_token": "must-not-export-token",
                "value": "safe",
                "reason": "Verify argument redaction",
                "user_intent": "Keep credentials out of Flowlines",
            },
            meta=self.meta(),
        )
        span = self.exporter.get_finished_spans()[0]
        captured = json.loads(span.attributes["gen_ai.tool.call.arguments"])
        self.assertEqual(captured["password"], "<redacted>")
        self.assertEqual(captured["environment"], "<redacted>")
        self.assertEqual(captured["headers"], "<redacted>")
        self.assertEqual(captured["service_token"], "<redacted>")
        self.assertEqual(captured["value"], "safe")
        serialized = span.attributes["gen_ai.tool.call.arguments"]
        self.assertNotIn("must-not-export", serialized)
        self.assertNotIn("must-not-export-env", serialized)
        self.assertNotIn("must-not-export-header", serialized)
        self.assertNotIn("must-not-export-token", serialized)

    async def test_secret_bearing_tool_result_is_replaced_for_telemetry_only(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="grabowski_secret_reveal", annotations=READ_ONLY)
        def reveal() -> dict[str, str]:
            return {"secret_text": "must-not-export"}

        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)
        result = await self.call(
            mcp,
            name="grabowski_secret_reveal",
            arguments={
                "reason": "Verify result redaction",
                "user_intent": "Keep break-glass secrets out of Flowlines",
            },
            meta=self.meta(),
        )
        self.assertEqual(result.root.structuredContent, {"secret_text": "must-not-export"})
        span = self.exporter.get_finished_spans()[0]
        captured = span.attributes["gen_ai.tool.call.result"]
        self.assertNotIn("must-not-export", captured)
        self.assertEqual(
            json.loads(captured),
            {"reason": "sensitive_tool_result", "redacted": True},
        )

    def test_api_key_header_must_be_present_and_nonempty(self) -> None:
        self.assertFalse(flowlines._has_flowlines_api_key(""))
        self.assertFalse(flowlines._has_flowlines_api_key("x-flowlines-api-key="))
        self.assertFalse(flowlines._has_flowlines_api_key("authorization=abc"))
        self.assertTrue(flowlines._has_flowlines_api_key("x-flowlines-api-key=present"))

    def test_exporter_initialization_failure_is_fail_open(self) -> None:
        with (
            mock.patch.dict(
                os.environ,
                {
                    "GRABOWSKI_FLOWLINES_ENABLED": "1",
                    "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
                    "OTEL_EXPORTER_OTLP_HEADERS": "x-flowlines-api-key=fixture",
                },
                clear=False,
            ),
            mock.patch(
                "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
                side_effect=RuntimeError("fixture exporter failure"),
            ),
        ):
            tracer, provider = flowlines._build_environment_tracer()

        self.assertIsNone(tracer)
        self.assertIsNone(provider)

    def test_owned_provider_force_flush_is_bounded(self) -> None:
        class Provider:
            def __init__(self) -> None:
                self.timeouts: list[int] = []

            def force_flush(self, timeout_millis: int) -> bool:
                self.timeouts.append(timeout_millis)
                return True

        provider = Provider()
        flowlines._bounded_flush(provider)
        self.assertEqual(provider.timeouts, [2_000])

    async def test_traceparent_is_propagated(self) -> None:
        mcp = self.server()
        await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Verify incoming trace context",
                "user_intent": "Correlate Flowlines with the caller trace",
            },
            meta=self.meta(),
            headers={
                "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
            },
        )
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(
            f"{span.context.trace_id:032x}",
            "0af7651916cd43dd8448eb211c80319c",
        )
        self.assertEqual(
            f"{span.parent.span_id:016x}",
            "b7ad6b7169203331",
        )


if __name__ == "__main__":
    unittest.main()

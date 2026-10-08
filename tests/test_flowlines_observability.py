from __future__ import annotations

import copy
import importlib
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

_PRIOR_MCP_MODULES = {
    name: module
    for name, module in tuple(sys.modules.items())
    if name == "mcp" or name.startswith("mcp.")
}
for name in tuple(_PRIOR_MCP_MODULES):
    sys.modules.pop(name, None)
try:
    from mcp.server.fastmcp import FastMCP
    from mcp.server.lowlevel.server import request_ctx
    from mcp.shared.context import RequestContext
    from mcp.types import CallToolRequest, ToolAnnotations

    _REAL_MCP_MODULES = {
        name: module
        for name, module in tuple(sys.modules.items())
        if name == "mcp" or name.startswith("mcp.")
    }
finally:
    for name in tuple(sys.modules):
        if name == "mcp" or name.startswith("mcp."):
            sys.modules.pop(name, None)
    sys.modules.update(_PRIOR_MCP_MODULES)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.sampling import ALWAYS_ON

import grabowski_flowlines as flowlines


READ_ONLY = ToolAnnotations(readOnlyHint=True)


class FlowlinesObservabilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        mcp_modules = mock.patch.dict(sys.modules, _REAL_MCP_MODULES, clear=False)
        mcp_modules.start()
        self.addCleanup(mcp_modules.stop)

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
        self.assertIn("For blocked work, report partial", report.description)
        self.assertIn("For blocked work, use partial", flowlines.FLOWLINES_INSTRUCTION)
        unmet_schema = report.parameters["properties"]["unmet_needs"]
        unmet_array = next(
            item for item in unmet_schema.get("anyOf", []) if item.get("type") == "array"
        )
        self.assertEqual(unmet_array.get("maxItems"), 16)
        self.assertEqual(unmet_array["items"].get("minLength"), 1)
        self.assertEqual(unmet_array["items"].get("maxLength"), 512)

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
        self.assertNotIn("user.name", attrs)
        self.assertNotIn("user.email", attrs)
        self.assertEqual(attrs["gen_ai.tool.call.reason"], "Read the fixture value")
        self.assertEqual(attrs["session.user_intent"], "Verify Flowlines instrumentation")

        public_arguments = json.loads(attrs["gen_ai.tool.call.arguments"])
        self.assertEqual(public_arguments["value"], "<redacted>")
        self.assertEqual(public_arguments["reason"], "Read the fixture value")
        self.assertEqual(public_arguments["user_intent"], "Verify Flowlines instrumentation")
        self.assertNotIn("_meta", public_arguments)

        captured_result = json.loads(attrs["gen_ai.tool.call.result"])
        self.assertEqual(
            captured_result,
            {"reason": "tool_result_content_disabled", "redacted": True},
        )

        declared = json.loads(attrs["gen_ai.tool.input_schema"])
        published = mcp._tool_manager.get_tool("echo").parameters
        self.assertEqual(declared, published)
        output = json.loads(attrs["gen_ai.tool.output_schema"])
        self.assertEqual(output, mcp._tool_manager.get_tool("echo").output_schema)

    async def test_free_text_telemetry_scrubs_credential_patterns(self) -> None:
        domain_value = "s" + "k-" + ("d" * 24)
        bare_token = "syntheticBareToken123456"
        bearer_token = "synthetic-bearer-token-value"
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": domain_value,
                "reason": f"Rotate token {bare_token}",
                "user_intent": f"Use Authorization: Bearer {bearer_token} safely",
            },
            meta=self.meta(),
        )

        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": domain_value})
        attrs = self.exporter.get_finished_spans()[0].attributes
        serialized = json.dumps(dict(attrs), sort_keys=True)
        self.assertNotIn(domain_value, serialized)
        self.assertNotIn(bare_token, serialized)
        self.assertNotIn(bearer_token, serialized)
        self.assertEqual(attrs["gen_ai.tool.call.reason"], "Rotate token <REDACTED>")
        self.assertEqual(
            attrs["session.user_intent"],
            "Use Authorization: <REDACTED> safely",
        )
        public_arguments = json.loads(attrs["gen_ai.tool.call.arguments"])
        self.assertEqual(public_arguments["reason"], "Rotate token <REDACTED>")
        self.assertEqual(
            public_arguments["user_intent"],
            "Use Authorization: <REDACTED> safely",
        )
        self.assertEqual(public_arguments["value"], "<redacted>")

    async def test_identifier_attributes_scrub_credential_patterns(self) -> None:
        provider_key = "s" + "k-proj-" + ("I" * 24)
        bearer_token = "synthetic-identifier-bearer-value"
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Verify identifier telemetry",
                "user_intent": "Keep client identifiers safe",
            },
            meta=self.meta(
                **{
                    "user.id": provider_key,
                    "session.id": f"session-{provider_key}",
                }
            ),
            request_id=f"Authorization: Bearer {bearer_token}",
        )

        self.assertFalse(result.root.isError)
        attrs = self.exporter.get_finished_spans()[0].attributes
        serialized = json.dumps(dict(attrs), sort_keys=True)
        self.assertNotIn(provider_key, serialized)
        self.assertNotIn(bearer_token, serialized)
        self.assertEqual(attrs["user.id"], "<REDACTED_OPENAI_KEY>")
        self.assertEqual(
            attrs["session.id"],
            "session-<REDACTED_OPENAI_KEY>",
        )
        self.assertEqual(
            attrs["mcp.request.id"],
            "Authorization: <REDACTED>",
        )

    async def test_bare_github_tokens_are_scrubbed_from_text_and_identifiers(self) -> None:
        classic_token = "ghp_" + ("G" * 32)
        fine_grained_token = "github_pat_" + ("H" * 32)
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": f"Rotate {classic_token}",
                "user_intent": f"Keep {fine_grained_token} private",
            },
            meta=self.meta(
                **{
                    "user.id": classic_token,
                    "session.id": f"session-{fine_grained_token}",
                }
            ),
            request_id=f"req-{classic_token}",
        )

        self.assertFalse(result.root.isError)
        attrs = self.exporter.get_finished_spans()[0].attributes
        serialized = json.dumps(dict(attrs), sort_keys=True)
        self.assertNotIn(classic_token, serialized)
        self.assertNotIn(fine_grained_token, serialized)
        self.assertIn("<REDACTED_GITHUB_TOKEN>", serialized)

    async def test_bare_gitlab_tokens_are_scrubbed_from_text_and_identifiers(self) -> None:
        personal_token = "glpat-" + ("L" * 26)
        deploy_token = "gldt-" + ("M" * 26)
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": f"Rotate {personal_token}",
                "user_intent": f"Keep {deploy_token} private",
            },
            meta=self.meta(
                **{
                    "user.id": personal_token,
                    "session.id": f"session-{deploy_token}",
                }
            ),
            request_id=f"req-{personal_token}",
        )

        self.assertFalse(result.root.isError)
        attrs = self.exporter.get_finished_spans()[0].attributes
        serialized = json.dumps(dict(attrs), sort_keys=True)
        self.assertNotIn(personal_token, serialized)
        self.assertNotIn(deploy_token, serialized)
        self.assertEqual(
            attrs["gen_ai.tool.call.reason"],
            "Rotate <REDACTED_GITLAB_TOKEN>",
        )
        self.assertEqual(
            attrs["session.user_intent"],
            "Keep <REDACTED_GITLAB_TOKEN> private",
        )
        self.assertEqual(attrs["user.id"], "<REDACTED_GITLAB_TOKEN>")
        self.assertEqual(
            attrs["session.id"],
            "session-<REDACTED_GITLAB_TOKEN>",
        )
        self.assertEqual(
            attrs["mcp.request.id"],
            "req-<REDACTED_GITLAB_TOKEN>",
        )


    async def test_bare_slack_tokens_are_scrubbed_from_text_and_identifiers(self) -> None:
        bot_token = "xoxb-" + ("B" * 28)
        app_token = "xapp-1-" + ("A" * 28)
        mcp = self.server()
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": f"Rotate {bot_token}",
                "user_intent": f"Keep {app_token} private",
            },
            meta=self.meta(
                **{
                    "user.id": bot_token,
                    "session.id": f"session-{app_token}",
                }
            ),
            request_id=f"req-{bot_token}",
        )

        self.assertFalse(result.root.isError)
        attrs = self.exporter.get_finished_spans()[0].attributes
        serialized = json.dumps(dict(attrs), sort_keys=True)
        self.assertNotIn(bot_token, serialized)
        self.assertNotIn(app_token, serialized)
        self.assertIn("<REDACTED_SLACK_TOKEN>", serialized)

    async def test_report_outcome_scrubs_sensitive_free_text_recursively(self) -> None:
        provider_key = "s" + "k-ant-" + ("x" * 24)
        gitlab_token = "glpat-" + ("N" * 26)
        password = "synthetic-password-value"
        mcp = FastMCP("grabowski-test", instructions="fixture")
        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)
        await self.call(
            mcp,
            name="report_outcome",
            arguments={
                "reason": f"Record secret={provider_key}",
                "user_intent": "Keep the outcome telemetry safe",
                "status": "partial",
                "outcome_summary": f"Credential {provider_key} was rotated.",
                "unmet_needs": [
                    f"Reset password={password}",
                    f"Rotate GitLab token {gitlab_token}",
                ],
            },
            meta=self.meta(),
        )

        attrs = self.exporter.get_finished_spans()[0].attributes
        serialized = json.dumps(dict(attrs), sort_keys=True)
        self.assertNotIn(provider_key, serialized)
        self.assertNotIn(gitlab_token, serialized)
        self.assertNotIn(password, serialized)
        public_arguments = json.loads(attrs["gen_ai.tool.call.arguments"])
        self.assertEqual(
            public_arguments["reason"],
            "Record secret=<REDACTED>",
        )
        self.assertEqual(
            public_arguments["user_intent"],
            "Keep the outcome telemetry safe",
        )
        self.assertEqual(public_arguments["status"], "partial")
        self.assertEqual(
            public_arguments["outcome_summary"],
            "Credential <REDACTED_ANTHROPIC_KEY> was rotated.",
        )
        self.assertEqual(
            public_arguments["unmet_needs"],
            [
                "Reset password=<REDACTED>",
                "Rotate GitLab token <REDACTED_GITLAB_TOKEN>",
            ],
        )

    def test_established_secret_classes_are_scrubbed(self) -> None:
        provider_key = "s" + "k-proj-" + ("A" * 24)
        aws_access_key = "AKIA" + ("B" * 16)
        private_key_label = "PRIVATE" + " KEY"
        private_key = (
            f"-----BEGIN {private_key_label}-----\n"
            "synthetic-private-material\n"
            f"-----END {private_key_label}-----"
        )
        github_classic = "ghp_" + ("C" * 32)
        github_fine_grained = "github_pat_" + ("D" * 32)
        gitlab_tokens = [
            f"{prefix}-" + ("E" * 26)
            for prefix in (
                "glpat",
                "gloas",
                "gldt",
                "glrt",
                "glrtr",
                "glcbt",
                "glptt",
                "glft",
                "glimt",
                "glagent",
                "glwt",
                "glsoat",
                "glffct",
            )
        ]
        slack_tokens = [
            "xoxb-" + ("S" * 28),
            "xoxp-" + ("P" * 28),
            "xapp-1-" + ("A" * 28),
        ]
        cases = [
            (f"provider {provider_key}", provider_key),
            (f"github {github_classic}", github_classic),
            (f"github {github_fine_grained}", github_fine_grained),
            *((f"gitlab {token}", token) for token in gitlab_tokens),
            *((f"slack {token}", token) for token in slack_tokens),
            (f"aws {aws_access_key}", aws_access_key),
            (private_key, "synthetic-private-material"),
            (
                "AWS_SECRET_ACCESS_KEY=synthetic-aws-secret-value",
                "synthetic-aws-secret-value",
            ),
            (
                "client-key-data: synthetic-client-key-data-value",
                "synthetic-client-key-data-value",
            ),
            ("Reset password=short", "short"),
            ("Use credential: abc123", "abc123"),
            ("authorization is abc123", "abc123"),
            (
                "authorization is syntheticBareToken123456",
                "syntheticBareToken123456",
            ),
            ("authorization Bearer abc123", "abc123"),
            ("password correcthorsebattery", "correcthorsebattery"),
            ("authorization huntertwo", "huntertwo"),
            ("token lowercasecredential", "lowercasecredential"),
            ("secret abc", "abc"),
        ]
        for value, secret in cases:
            with self.subTest(value=value.splitlines()[0][:48]):
                redacted = flowlines._redact_sensitive_text(value)
                self.assertNotIn(secret, redacted)
                self.assertIn("<REDACTED", redacted)

    def test_benign_analytics_text_is_preserved(self) -> None:
        samples = [
            "Verify Flowlines instrumentation",
            "Rotate credentials without exposing repository context",
            "Use token bucket metadata for rate-limit analysis",
            "Review token authentication requirements",
            "Review secret authentication requirements",
            "Review password authentication requirements",
            "Inspect credential requirements for the operator",
            "Authorization is required for this operation",
            "Authorization is OpenID metadata",
            "Review authorization authentication requirements",
            "Discuss glpat-prefix handling without a token",
            "Record the partial outcome and remaining operator gate",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                self.assertEqual(flowlines._redact_sensitive_text(sample), sample)

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

    def test_standalone_contract_can_skip_environment_exporter(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="echo", annotations=READ_ONLY)
        def echo(value: str) -> dict[str, str]:
            return {"value": value}

        with mock.patch.object(flowlines, "_build_environment_tracer") as build:
            state = flowlines.configure_flowlines_observability(
                mcp,
                READ_ONLY,
                load_environment_exporter=False,
            )

        build.assert_not_called()
        self.assertFalse(state["export_enabled"])
        self.assertIsNotNone(
            mcp._tool_manager.get_tool(flowlines.REPORT_OUTCOME_TOOL)
        )
        published = mcp._tool_manager.get_tool("echo").parameters
        self.assertTrue({"reason", "user_intent"}.issubset(published["required"]))

    def test_existing_domain_analytics_schemas_are_not_overwritten(self) -> None:
        tool = SimpleNamespace(
            name="domain_fields",
            parameters={
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "enum": ["domain-reason"],
                        "description": "Domain-owned reason semantics.",
                    },
                    "user_intent": {
                        "type": "string",
                        "pattern": "^domain-",
                        "description": "Domain-owned intent semantics.",
                    },
                },
                "required": ["reason"],
            },
        )
        before = copy.deepcopy(tool.parameters["properties"])
        flowlines._augment_tool_schema(tool)
        self.assertEqual(tool.parameters["properties"], before)
        self.assertTrue(
            {"reason", "user_intent"}.issubset(set(tool.parameters["required"]))
        )

    async def test_existing_domain_reason_arguments_are_preserved(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")
        seen: dict[str, str] = {}

        @mcp.tool(name="required_domain_reason", annotations=READ_ONLY)
        def required_domain_reason(reason: str) -> dict[str, str]:
            seen["required"] = reason
            return {"reason": reason}

        @mcp.tool(name="optional_domain_reason", annotations=READ_ONLY)
        def optional_domain_reason(reason: str = "") -> dict[str, str]:
            seen["optional"] = reason
            return {"reason": reason}

        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)

        long_required_reason = "required-domain-reason-" + ("r" * 160)
        long_optional_reason = "optional-domain-reason-" + ("o" * 160)
        for tool_name, value in (
            ("required_domain_reason", long_required_reason),
            ("optional_domain_reason", long_optional_reason),
        ):
            result = await self.call(
                mcp,
                name=tool_name,
                arguments={
                    "reason": value,
                    "user_intent": "Verify Flowlines preserves domain reason fields",
                },
                meta=self.meta(),
            )
            self.assertFalse(result.root.isError)
            self.assertEqual(result.root.structuredContent, {"reason": value})

        self.assertEqual(seen["required"], long_required_reason)
        self.assertEqual(seen["optional"], long_optional_reason)
        spans = self.exporter.get_finished_spans()
        self.assertEqual(len(spans), 2)
        self.assertEqual(
            [span.attributes["gen_ai.tool.call.reason"] for span in spans],
            [long_required_reason, long_optional_reason],
        )

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

    async def test_missing_client_session_reports_once_without_private_data(self) -> None:
        mcp = self.server(verified_resolver=lambda _ctx: {"id": "verified-test-user"})
        arguments = {
            "value": "private-value-do-not-log",
            "reason": "Reason contains private-reason-do-not-log",
            "user_intent": "private-intent-do-not-log",
        }
        with self.assertLogs(flowlines.LOGGER, level="WARNING") as records:
            for _ in range(2):
                result = await self.call(
                    mcp,
                    arguments=arguments,
                    meta={"user.id": "spoofed-test-user", "user.email": "private@example.invalid"},
                )
                self.assertFalse(result.root.isError)
        self.assertEqual(self.exporter.get_finished_spans(), ())
        self.assertEqual(len(records.output), 1)
        self.assertIn("client_session_id_missing", records.output[0])
        for secret in (
            "private-value-do-not-log",
            "private-reason-do-not-log",
            "private-intent-do-not-log",
            "spoofed-test-user",
            "private@example.invalid",
        ):
            self.assertNotIn(secret, records.output[0])

    async def test_failing_diagnostic_logger_keeps_domain_call_fail_open(self) -> None:
        mcp = self.server(verified_resolver=lambda _ctx: {"id": "verified-test-user"})
        with mock.patch.object(
            flowlines.LOGGER, "warning", side_effect=RuntimeError("logging transport unavailable")
        ):
            result = await self.call(
                mcp,
                arguments={
                    "value": "hello",
                    "reason": "Read the fixture value",
                    "user_intent": "Verify diagnostics stay fail-open",
                },
                meta={},
            )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": "hello"})
        self.assertEqual(self.exporter.get_finished_spans(), ())

    async def test_verified_identity_failure_reports_bounded_reason_once(self) -> None:
        mcp = self.server(verified_resolver=lambda _ctx: (_ for _ in ()).throw(RuntimeError("private-transport-detail")))
        with self.assertLogs(flowlines.LOGGER, level="WARNING") as records:
            result = await self.call(
                mcp,
                arguments={
                    "value": "private-value",
                    "reason": "Check identity",
                    "user_intent": "Verify Flowlines diagnostic",
                },
                meta=self.meta(),
            )
        self.assertFalse(result.root.isError)
        self.assertEqual(self.exporter.get_finished_spans(), ())
        self.assertEqual(len(records.output), 1)
        self.assertIn("verified_connector_identity_unavailable", records.output[0])
        self.assertNotIn("private-transport-detail", records.output[0])

    async def test_span_setup_failure_is_fail_open_and_calls_domain_once(self) -> None:
        calls = 0
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="echo", annotations=READ_ONLY)
        def echo(value: str) -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"value": value}

        class FailingTracer:
            def start_as_current_span(self, *args, **kwargs):
                del args, kwargs
                raise RuntimeError("fixture span setup failure")

        flowlines.configure_flowlines_observability(
            mcp,
            READ_ONLY,
            tracer=FailingTracer(),
        )
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Exercise telemetry setup failure",
                "user_intent": "Verify Flowlines fail-open behavior",
            },
            meta=self.meta(),
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": "hello"})
        self.assertEqual(calls, 1)

    async def test_span_close_failure_is_fail_open_and_calls_domain_once(self) -> None:
        calls = 0
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="echo", annotations=READ_ONLY)
        def echo(value: str) -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"value": value}

        class Span:
            def set_status(self, *args, **kwargs):
                del args, kwargs

            def set_attribute(self, *args, **kwargs):
                del args, kwargs

        class FailingSpanContext:
            def __enter__(self):
                return Span()

            def __exit__(self, exc_type, exc, traceback):
                del exc_type, exc, traceback
                raise RuntimeError("fixture span close failure")

        class FailingTracer:
            def start_as_current_span(self, *args, **kwargs):
                del args, kwargs
                return FailingSpanContext()

        flowlines.configure_flowlines_observability(
            mcp,
            READ_ONLY,
            tracer=FailingTracer(),
        )
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Exercise telemetry close failure",
                "user_intent": "Verify Flowlines fail-open behavior",
            },
            meta=self.meta(),
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": "hello"})
        self.assertEqual(calls, 1)

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
        self.assertNotIn("user.name", span.attributes)
        self.assertNotIn("user.email", span.attributes)

    async def test_verified_identity_resolver_failure_does_not_fallback_to_client_identity(self) -> None:
        def broken_resolver(_ctx):
            raise RuntimeError("verified identity unavailable")

        mcp = self.server(verified_resolver=broken_resolver)
        result = await self.call(
            mcp,
            arguments={
                "value": "hello",
                "reason": "Read the fixture value",
                "user_intent": "Verify resolver failure isolation",
            },
            meta=self.meta(**{"user.id": "spoofed"}),
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"value": "hello"})
        self.assertEqual(self.exporter.get_finished_spans(), ())

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

    def test_ordinary_tool_payload_values_are_redacted_by_default(self) -> None:
        marker = "SYNTHETIC_SECRET_ARGUMENT_PAYLOAD"
        cases = {
            "grabowski_create_text": {
                "path": "/tmp/synthetic-private-path",
                "content": marker,
                "reason": "Create the requested text",
                "user_intent": "Verify default Flowlines argument privacy",
            },
            "grabowski_terminal_run": {
                "argv": ["printf", marker],
                "cwd": "/tmp/synthetic-private-cwd",
                "reason": "Run the requested command",
                "user_intent": "Verify default Flowlines argument privacy",
            },
            "generic_tool": {
                "stdin": marker,
                "reason": "Process provided input",
                "user_intent": "Verify default Flowlines argument privacy",
            },
        }

        for tool_name, arguments in cases.items():
            with self.subTest(tool_name=tool_name):
                captured = flowlines._telemetry_arguments(tool_name, arguments)
                serialized = flowlines._canonical_json(captured)
                self.assertNotIn(marker, serialized)
                self.assertEqual(captured["reason"], arguments["reason"])
                self.assertEqual(captured["user_intent"], arguments["user_intent"])
                for key in set(arguments) - {"reason", "user_intent"}:
                    self.assertEqual(captured[key], "<redacted>")

    async def test_sensitive_argument_keys_are_redacted_from_telemetry(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")

        @mcp.tool(name="credential_tool", annotations=READ_ONLY)
        def credential_tool(
            password: str,
            environment: dict[str, str],
            headers: dict[str, str],
            service_token: str,
            session_escalation: dict[str, str],
            argv: list[str],
            writer_argv: list[str],
            justification: str,
            note: str,
            evidence: dict[str, str],
            route_evidence: dict[str, str],
            external_closeout_evidence: dict[str, str],
            value: str,
        ) -> dict[str, str]:
            return {
                "value": value,
                "password_seen": str(bool(password)),
                "environment_seen": str(bool(environment)),
                "headers_seen": str(bool(headers)),
                "token_seen": str(bool(service_token)),
                "session_escalation_seen": str(bool(session_escalation)),
                "argv_seen": str(bool(argv)),
                "writer_argv_seen": str(bool(writer_argv)),
                "justification_seen": str(bool(justification)),
                "note_seen": str(bool(note)),
                "evidence_seen": str(bool(evidence)),
                "route_evidence_seen": str(bool(route_evidence)),
                "external_closeout_evidence_seen": str(bool(external_closeout_evidence)),
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
                "session_escalation": {"recovery": "must-not-export-escalation"},
                "argv": ["must-not-export-argv"],
                "writer_argv": ["must-not-export-writer-argv"],
                "justification": "must-not-export-justification",
                "note": "must-not-export-note",
                "evidence": {"detail": "must-not-export-evidence"},
                "route_evidence": {"detail": "must-not-export-route-evidence"},
                "external_closeout_evidence": {"detail": "must-not-export-closeout-evidence"},
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
        self.assertEqual(captured["session_escalation"], "<redacted>")
        self.assertEqual(captured["argv"], "<redacted>")
        self.assertEqual(captured["writer_argv"], "<redacted>")
        self.assertEqual(captured["justification"], "<redacted>")
        self.assertEqual(captured["note"], "<redacted>")
        self.assertEqual(captured["evidence"], "<redacted>")
        self.assertEqual(captured["route_evidence"], "<redacted>")
        self.assertEqual(captured["external_closeout_evidence"], "<redacted>")
        self.assertEqual(captured["value"], "<redacted>")
        serialized = span.attributes["gen_ai.tool.call.arguments"]
        self.assertNotIn("must-not-export", serialized)
        self.assertNotIn("must-not-export-env", serialized)
        self.assertNotIn("must-not-export-header", serialized)
        self.assertNotIn("must-not-export-token", serialized)
        self.assertNotIn("must-not-export-escalation", serialized)
        self.assertNotIn("must-not-export-argv", serialized)
        self.assertNotIn("must-not-export-writer-argv", serialized)
        self.assertNotIn("must-not-export-justification", serialized)
        self.assertNotIn("must-not-export-note", serialized)
        self.assertNotIn("must-not-export-evidence", serialized)
        self.assertNotIn("must-not-export-route-evidence", serialized)
        self.assertNotIn("must-not-export-closeout-evidence", serialized)

    def test_content_bearing_argument_fields_are_redacted_by_default(self) -> None:
        marker = "synthetic-private-argument-content"
        cases = {
            "grabowski_secret_use": {"argv"},
            "grabowski_create_text": {"content"},
            "grabowski_replace_text": {"content"},
            "repoground_query": {"query"},
            "repoground_query_existing_index": {"query"},
            "repoground_context_pack": {"query"},
            "repoground_context_compose": {"query"},
            "repoground_agent_handoff": {"query"},
            "grabowski_terminal_run": {"argv"},
            "grabowski_job_start": {"argv"},
            "grabowski_git": {"arguments"},
            "grabowski_github": {"arguments"},
            "grabowski_tmux_send": {"text"},
            "grabowski_fleet_run": {"argv"},
            "grabowski_power_run": {"argv"},
            "grabowski_task_start": {"argv"},
            "grip_run": {"parameters"},
            "grabowski_juno_run": {"code"},
            "grabowski_browser_worker_semantic": {"navigation_target"},
            "grabowski_bureau_candidate_record": {"request"},
            "grabowski_bureau_task_propose": {"task_json", "placeholder_justification"},
            "grabowski_context_fabric_compose": {"binding", "observations"},
            "grabowski_context_fabric_explain": {"composed_context"},
            "grabowski_context_fabric_compare": {"baseline", "candidate"},
            "grabowski_operation_plan": {"parameters"},
            "grabowski_operation_run": {"parameters"},
            "grabowski_operator_recall_export": {"sources"},
            "grabowski_operational_guidance": {"symptoms"},
            "grabowski_agent_competition_start": {"task", "primary_summary"},
            "grabowski_context_fabric_plan": {"binding"},
            "grabowski_bureau_pickup_execute": {"request"},
            "ipad_file_create": {"payload_b64"},
            "ipad_file_replace": {"payload_b64"},
        }
        for tool_name, fields in cases.items():
            with self.subTest(tool_name=tool_name):
                arguments = {
                    "safe_metadata": "must-not-export-even-when-benignly-named",
                    "reason": "Preserve only the analytics reason",
                    "user_intent": "Preserve only the analytics intent",
                }
                for field in fields:
                    if field in {"argv", "arguments"}:
                        arguments[field] = [marker]
                    elif field in {
                        "parameters",
                        "request",
                        "task_json",
                        "binding",
                        "composed_context",
                        "baseline",
                        "candidate",
                        "sources",
                    }:
                        arguments[field] = {"payload": marker}
                    elif field == "observations":
                        arguments[field] = [{"payload": marker}]
                    elif field == "symptoms":
                        arguments[field] = [marker]
                    else:
                        arguments[field] = marker
                captured = flowlines._telemetry_arguments(tool_name, arguments)
                for field in fields:
                    self.assertEqual(captured[field], "<redacted>")
                self.assertEqual(captured["safe_metadata"], "<redacted>")
                self.assertEqual(captured["reason"], "Preserve only the analytics reason")
                self.assertEqual(captured["user_intent"], "Preserve only the analytics intent")
                self.assertNotIn(marker, json.dumps(captured))

    def test_ordinary_successful_result_content_is_disabled_by_default(self) -> None:
        marker = "synthetic-private-future-tool-result"

        class Result:
            isError = False

            def model_dump(self, **kwargs):
                del kwargs
                return {
                    "path": "/private/future/path",
                    "purpose": marker,
                    "nested": {"value": marker},
                }

        captured = flowlines._safe_result_json(
            Result(),
            tool_name="future_published_tool",
        )
        self.assertIsNotNone(captured)
        self.assertNotIn(marker, captured)
        self.assertEqual(
            json.loads(captured),
            {"reason": "tool_result_content_disabled", "redacted": True},
        )

    def test_api_key_header_must_be_present_and_nonempty(self) -> None:
        self.assertFalse(flowlines._has_flowlines_api_key(""))
        self.assertFalse(flowlines._has_flowlines_api_key("x-flowlines-api-key="))
        self.assertFalse(flowlines._has_flowlines_api_key("authorization=abc"))
        self.assertTrue(flowlines._has_flowlines_api_key("x-flowlines-api-key=present"))

    def test_api_key_header_rejects_extra_or_duplicate_headers(self) -> None:
        self.assertFalse(
            flowlines._has_flowlines_api_key(
                "x-flowlines-api-key=present,authorization=secret"
            )
        )
        self.assertFalse(
            flowlines._has_flowlines_api_key(
                "x-flowlines-api-key=first,x-flowlines-api-key=second"
            )
        )

    def test_ambient_credential_overrides_disable_export(self) -> None:
        base = {
            "GRABOWSKI_FLOWLINES_ENABLED": "1",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
            "OTEL_EXPORTER_OTLP_HEADERS": "x-flowlines-api-key=fixture",
        }
        for name in flowlines._FLOWLINES_FORBIDDEN_EXPORT_ENV:
            with self.subTest(name=name), mock.patch.dict(
                os.environ,
                {**base, name: "fixture-override"},
                clear=True,
            ):
                tracer, provider = flowlines._build_environment_tracer()
                self.assertIsNone(tracer)
                self.assertIsNone(provider)

    def test_trace_specific_header_is_consumed_when_export_is_rejected(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GRABOWSKI_FLOWLINES_ENABLED": "1",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
                "OTEL_EXPORTER_OTLP_HEADERS": "x-flowlines-api-key=fixture",
                "OTEL_EXPORTER_OTLP_TRACES_HEADERS": "x-flowlines-api-key=trace-fixture",
            },
            clear=True,
        ):
            tracer, provider = flowlines._build_environment_tracer()
            self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS", os.environ)
            self.assertNotIn("OTEL_EXPORTER_OTLP_TRACES_HEADERS", os.environ)

        self.assertIsNone(tracer)
        self.assertIsNone(provider)

    def test_malformed_endpoint_port_disables_export_without_raising(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GRABOWSKI_FLOWLINES_ENABLED": "1",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai:notaport",
            },
            clear=True,
        ):
            tracer, provider = flowlines._build_environment_tracer()
        self.assertIsNone(tracer)
        self.assertIsNone(provider)

    def test_exporter_is_bound_to_flowlines_and_bounded_processor(self) -> None:
        base = {
            "GRABOWSKI_FLOWLINES_ENABLED": "1",
            "OTEL_SERVICE_NAME": "ambient-service-name-must-not-win",
            "OTEL_RESOURCE_ATTRIBUTES": "secret.env=must-not-export-resource",
        }

        class Provider:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.processors = []

            def add_span_processor(self, processor):
                self.processors.append(processor)

            def get_tracer(self, name):
                return ("tracer", name)

        provider = Provider()
        exporter = object()
        processor = object()
        exporter_module = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter"
        )
        trace_module = importlib.import_module("opentelemetry.sdk.trace")
        trace_export_module = importlib.import_module("opentelemetry.sdk.trace.export")
        with (
            mock.patch.dict(os.environ, base, clear=True),
            mock.patch.object(
                flowlines,
                "_load_flowlines_api_key",
                return_value="fixture",
            ) as credential_loader,
            mock.patch.object(
                exporter_module,
                "OTLPSpanExporter",
                return_value=exporter,
            ) as exporter_factory,
            mock.patch.object(
                trace_module,
                "TracerProvider",
                return_value=provider,
            ) as provider_factory,
            mock.patch.object(
                trace_export_module,
                "BatchSpanProcessor",
                return_value=processor,
            ) as processor_factory,
        ):
            tracer, returned_provider = flowlines._build_environment_tracer()

        credential_loader.assert_called_once_with()
        self.assertEqual(tracer, ("tracer", "grabowski.flowlines"))
        self.assertIs(returned_provider, provider)
        exporter_factory.assert_called_once_with(
            endpoint="https://api.flowlines.ai/v1/traces",
            headers={"x-flowlines-api-key": "fixture"},
            timeout=5.0,
            max_request_size=8 * 1024 * 1024,
        )
        processor_factory.assert_called_once_with(
            exporter,
            max_queue_size=512,
            schedule_delay_millis=1_000,
            max_export_batch_size=64,
            export_timeout_millis=5_000,
        )
        self.assertEqual(provider.processors, [processor])
        self.assertEqual(
            dict(provider_factory.call_args.kwargs["resource"].attributes),
            {"service.name": "grabowski-mcp"},
        )
        self.assertFalse(provider_factory.call_args.kwargs["shutdown_on_exit"])

    def test_exporter_initialization_failure_is_fail_open(self) -> None:
        exporter_module = importlib.import_module(
            "opentelemetry.exporter.otlp.proto.http.trace_exporter"
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "GRABOWSKI_FLOWLINES_ENABLED": "1",
                },
                clear=True,
            ),
            mock.patch.object(
                flowlines,
                "_load_flowlines_api_key",
                return_value="fixture",
            ) as credential_loader,
            mock.patch.object(
                exporter_module,
                "OTLPSpanExporter",
                side_effect=RuntimeError("fixture exporter failure"),
            ),
        ):
            tracer, provider = flowlines._build_environment_tracer()

        credential_loader.assert_called_once_with()
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

    async def test_report_outcome_returns_local_acceptance_and_is_traced(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")
        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)
        result = await self.call(
            mcp,
            name="report_outcome",
            arguments={
                "reason": "Close the Flowlines test session",
                "user_intent": "Verify Flowlines outcome reporting",
                "status": "accomplished",
                "outcome_summary": "The local report was accepted.",
                "unmet_needs": [],
            },
            meta=self.meta(),
        )
        self.assertFalse(result.root.isError)
        self.assertEqual(result.root.structuredContent, {"accepted": True})
        span = self.exporter.get_finished_spans()[0]
        self.assertEqual(span.attributes["gen_ai.tool.name"], "report_outcome")
        public_arguments = json.loads(span.attributes["gen_ai.tool.call.arguments"])
        self.assertEqual(public_arguments["status"], "accomplished")
        self.assertEqual(public_arguments["outcome_summary"], "The local report was accepted.")
        self.assertEqual(public_arguments["unmet_needs"], [])
        self.assertEqual(public_arguments["reason"], "Close the Flowlines test session")
        self.assertEqual(public_arguments["user_intent"], "Verify Flowlines outcome reporting")
        self.assertEqual(
            json.loads(span.attributes["gen_ai.tool.call.result"])["structuredContent"],
            {"accepted": True},
        )

    async def test_report_outcome_rejects_blocked_status(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")
        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)

        result = await self.call(
            mcp,
            name="report_outcome",
            arguments={
                "reason": "Record an operator block",
                "user_intent": "Represent blocked work with a supported outcome status",
                "status": "blocked",
                "outcome_summary": "A required operator gate blocked completion.",
                "unmet_needs": ["Clear the operator gate."],
            },
            meta=self.meta(),
        )

        self.assertTrue(result.root.isError)
        self.assertEqual(self.exporter.get_finished_spans(), ())

    async def test_report_outcome_rejects_unbounded_unmet_needs(self) -> None:
        mcp = FastMCP("grabowski-test", instructions="fixture")
        flowlines.configure_flowlines_observability(mcp, READ_ONLY, tracer=self.tracer)

        base = {
            "reason": "Validate bounded outcome telemetry",
            "user_intent": "Keep Flowlines terminal reports bounded",
            "status": "partial",
            "outcome_summary": "Some work remains.",
        }
        too_many = await self.call(
            mcp,
            name="report_outcome",
            arguments={**base, "unmet_needs": ["item"] * 17},
            meta=self.meta(),
        )
        too_long = await self.call(
            mcp,
            name="report_outcome",
            arguments={**base, "unmet_needs": ["x" * 513]},
            meta=self.meta(),
        )

        self.assertTrue(too_many.root.isError)
        self.assertTrue(too_long.root.isError)
        self.assertEqual(self.exporter.get_finished_spans(), ())

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

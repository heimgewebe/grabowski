from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _worker_main(scenario: str) -> None:
    if str(SRC) not in sys.path:
        sys.path.insert(0, str(SRC))

    from mcp.server.fastmcp import FastMCP
    from mcp.server.lowlevel.server import request_ctx
    from mcp.shared.context import RequestContext
    from mcp.types import CallToolRequest
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
    from opentelemetry.sdk.trace.sampling import ALWAYS_ON
    from posthog.mcp import instrument
    from posthog.mcp.types import MCPAnalyticsOptions

    import grabowski_flowlines as flowlines
    import grabowski_operator as operator

    class CapturingPostHog:
        def __init__(self, *, fail_capture: bool = False) -> None:
            self.events: list[dict[str, object]] = []
            self.fail_capture = fail_capture
            self.library_identity: tuple[str, str] | None = None

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
            return None

    class FailingTracer:
        def start_as_current_span(self, *args, **kwargs):
            del args, kwargs
            raise RuntimeError("flowlines fixture span setup failure")

    exporter = InMemorySpanExporter()
    provider = TracerProvider(sampler=ALWAYS_ON)
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("tests.observability-interaction")
    prior_gate_installed = operator._DEPLOYMENT_ADMISSION_GATE_INSTALLED

    def posthog_options() -> MCPAnalyticsOptions:
        return MCPAnalyticsOptions(
            report_missing=False,
            enable_conversation_id=False,
            enable_exception_autocapture=False,
            context=False,
            capture_model=False,
            collect_feedback=False,
            before_send=operator._posthog_metadata_only_before_send,
        )

    def server(selected_tracer):
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
            tracer=selected_tracer,
        )
        return mcp, calls

    async def call(mcp: FastMCP, *, secret: str, user_intent: str):
        request = CallToolRequest(
            params={
                "name": "combined_observe",
                "arguments": {
                    "authorization": secret,
                    "reason": "domain-owned reason",
                    "user_intent": user_intent,
                },
                "_meta": {
                    "session.id": "combined-session",
                    "user.id": "combined-user",
                },
            }
        )
        context = RequestContext(
            request_id=77,
            meta=request.params.meta,
            session=SimpleNamespace(),
            lifespan_context={},
            request=SimpleNamespace(
                headers={"mcp-session-id": "transport-session"}
            ),
        )
        token = request_ctx.set(context)
        try:
            handler = mcp._mcp_server.request_handlers[CallToolRequest]
            return await handler(request)
        finally:
            request_ctx.reset(token)

    def install_posthog_then_http_gate(
        mcp: FastMCP,
        client: CapturingPostHog,
    ) -> None:
        instrument(mcp, client, posthog_options())
        with mock.patch.object(operator, "mcp", mcp):
            operator._configure_http_runtime()
        if not getattr(
            mcp._tool_manager.call_tool,
            "_grabowski_deployment_admission_gate",
            False,
        ):
            raise AssertionError("Grabowski HTTP/authority gate is not outermost")

    async def run() -> None:
        if scenario == "combined":
            secret = "Bearer private-combined-secret"
            private_intent = "private combined user intent"
            mcp, calls = server(tracer)
            client = CapturingPostHog()
            install_posthog_then_http_gate(mcp, client)

            result = await call(mcp, secret=secret, user_intent=private_intent)
            if result.root.isError:
                raise AssertionError("combined domain call returned an error")
            if result.root.structuredContent != {
                "payload": "private-result-marker"
            }:
                raise AssertionError("combined domain result changed")
            if calls != [
                {
                    "authorization": secret,
                    "reason": "domain-owned reason",
                }
            ]:
                raise AssertionError("domain call was not exactly-once and intact")

            spans = exporter.get_finished_spans()
            if len(spans) != 1:
                raise AssertionError(f"expected one Flowlines span, got {len(spans)}")
            span = spans[0]
            if span.attributes["gen_ai.tool.name"] != "combined_observe":
                raise AssertionError("Flowlines tool name changed")
            if span.attributes["gen_ai.tool.call.reason"] != "domain-owned reason":
                raise AssertionError("Flowlines lost domain reason")
            if span.attributes["session.user_intent"] != private_intent:
                raise AssertionError("Flowlines lost user intent")
            flowline_arguments = json.loads(
                span.attributes["gen_ai.tool.call.arguments"]
            )
            if flowline_arguments["authorization"] != "<redacted>":
                raise AssertionError("Flowlines did not redact authorization")
            if flowline_arguments["reason"] != "domain-owned reason":
                raise AssertionError("Flowlines argument evidence lost reason")
            if flowline_arguments["user_intent"] != private_intent:
                raise AssertionError("Flowlines argument evidence lost user intent")

            if len(client.events) != 1:
                raise AssertionError(
                    f"expected one PostHog event, got {len(client.events)}"
                )
            event = client.events[0]
            if event["event"] != "$mcp_tool_call":
                raise AssertionError("unexpected PostHog event")
            if event["distinct_id"] != operator.POSTHOG_DISTINCT_ID:
                raise AssertionError("PostHog distinct id is not anonymous")
            properties = event["properties"]
            if not isinstance(properties, dict):
                raise AssertionError("PostHog properties are not an object")
            if properties["$mcp_tool_name"] != "combined_observe":
                raise AssertionError("PostHog tool name changed")
            if properties["$mcp_is_error"]:
                raise AssertionError("PostHog marked successful call as error")
            if not properties["$geoip_disable"]:
                raise AssertionError("PostHog GeoIP suppression missing")
            if properties["$process_person_profile"]:
                raise AssertionError("PostHog person profile suppression missing")
            allowed = set(operator.POSTHOG_METADATA_PROPERTIES) | {
                "$geoip_disable",
                "$process_person_profile",
            }
            if not set(properties).issubset(allowed):
                raise AssertionError("PostHog emitted non-metadata properties")
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
                if forbidden in encoded_event:
                    raise AssertionError(
                        f"PostHog event leaked forbidden value: {forbidden}"
                    )
            return

        if scenario == "posthog-failure":
            mcp, calls = server(tracer)
            client = CapturingPostHog(fail_capture=True)
            install_posthog_then_http_gate(mcp, client)
            result = await call(
                mcp,
                secret="Bearer posthog-failure-secret",
                user_intent="verify PostHog failure isolation",
            )
            if result.root.isError or len(calls) != 1:
                raise AssertionError("PostHog failure broke exactly-once domain call")
            spans = exporter.get_finished_spans()
            if len(spans) != 1 or spans[0].status.status_code.name != "OK":
                raise AssertionError("PostHog failure broke Flowlines span")
            if client.events:
                raise AssertionError("failed PostHog capture was recorded")
            return

        if scenario == "flowlines-failure":
            mcp, calls = server(FailingTracer())
            client = CapturingPostHog()
            install_posthog_then_http_gate(mcp, client)
            result = await call(
                mcp,
                secret="Bearer flowlines-failure-secret",
                user_intent="verify Flowlines failure isolation",
            )
            if result.root.isError or len(calls) != 1:
                raise AssertionError("Flowlines failure broke exactly-once domain call")
            if exporter.get_finished_spans():
                raise AssertionError("failing Flowlines tracer emitted spans")
            if len(client.events) != 1:
                raise AssertionError("Flowlines failure broke PostHog capture")
            if client.events[0]["event"] != "$mcp_tool_call":
                raise AssertionError("unexpected PostHog event after Flowlines failure")
            if (
                client.events[0]["properties"]["$mcp_tool_name"]
                != "combined_observe"
            ):
                raise AssertionError("PostHog lost tool name after Flowlines failure")
            return

        raise AssertionError(f"unknown worker scenario: {scenario}")

    try:
        asyncio.run(run())
    finally:
        operator._DEPLOYMENT_ADMISSION_GATE_INSTALLED = prior_gate_installed
        provider.shutdown()


class ObservabilityInteractionTests(unittest.TestCase):
    def _run_worker(self, scenario: str) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                scenario,
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=(
                f"observability worker {scenario!r} failed\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            ),
        )

    def test_real_wrapper_stack_executes_once_and_separates_privacy_domains(self) -> None:
        self._run_worker("combined")

    def test_posthog_capture_failure_does_not_break_flowlines_or_domain(self) -> None:
        self._run_worker("posthog-failure")

    def test_flowlines_span_setup_failure_does_not_break_posthog_or_domain(self) -> None:
        self._run_worker("flowlines-failure")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        _worker_main(sys.argv[2])
    else:
        unittest.main()

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_TEST = ROOT / "tests" / "test_operator_contract.py"


def _contract_module():
    spec = importlib.util.spec_from_file_location(
        "grabowski_posthog_contract_fixture", CONTRACT_TEST
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load operator contract fixture")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PostHogMCPAnalyticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _contract_module()
        self.operator = self.fixture._load_operator_module()

    def tearDown(self) -> None:
        self.operator._POSTHOG_MCP_CLIENT = None
        self.operator._POSTHOG_MCP_ANALYTICS = None

    def test_metadata_projection_is_strictly_content_free(self) -> None:
        event = {
            "event": "$mcp_tool_call",
            "distinct_id": "real-user",
            "timestamp": "2026-10-02T12:00:00Z",
            "properties": {
                "$mcp_tool_name": "grabowski_status",
                "$mcp_duration_ms": 12.5,
                "$mcp_is_error": False,
                "$mcp_server_name": "Grabowski",
                "$mcp_protocol_version": "2025-06-18",
                "$mcp_source": "posthog_mcp_analytics",
                "$session_id": "session-safe-id",
                "$mcp_parameters": {"token": "secret"},
                "$mcp_response": {"private": "payload"},
                "$mcp_intent": "private user goal",
                "$mcp_llm_model": "model-name",
                "$mcp_error_message": "private error text",
                "custom_property": "must-not-leave",
            },
        }
        projected = self.operator._posthog_metadata_only_before_send(event)
        self.assertIsNotNone(projected)
        assert projected is not None
        self.assertEqual(projected["event"], "$mcp_tool_call")
        self.assertEqual(
            projected["distinct_id"], self.operator.POSTHOG_DISTINCT_ID
        )
        self.assertEqual(projected["timestamp"], event["timestamp"])
        properties = projected["properties"]
        self.assertEqual(properties["$mcp_tool_name"], "grabowski_status")
        self.assertEqual(properties["$mcp_duration_ms"], 12.5)
        self.assertFalse(properties["$mcp_is_error"])
        self.assertEqual(properties["$session_id"], "session-safe-id")
        self.assertTrue(properties["$geoip_disable"])
        self.assertFalse(properties["$process_person_profile"])
        for forbidden in (
            "$mcp_parameters",
            "$mcp_response",
            "$mcp_intent",
            "$mcp_llm_model",
            "$mcp_error_message",
            "custom_property",
        ):
            self.assertNotIn(forbidden, properties)

    def test_non_tool_events_and_malformed_tool_events_are_dropped(self) -> None:
        self.assertIsNone(
            self.operator._posthog_metadata_only_before_send(
                {"event": "$exception", "properties": {}}
            )
        )
        self.assertIsNone(
            self.operator._posthog_metadata_only_before_send(
                {
                    "event": "$mcp_tool_call",
                    "properties": {"$mcp_tool_name": "read"},
                }
            )
        )

    def test_invalid_host_fails_open_without_importing_posthog(self) -> None:
        with patch.dict(
            self.operator.os.environ,
            {
                self.operator.POSTHOG_MCP_ANALYTICS_SWITCH_ENV: "1",
                self.operator.POSTHOG_PROJECT_TOKEN_ENV: "phc_test",
                self.operator.POSTHOG_HOST_ENV: "https://example.invalid",
            },
            clear=False,
        ):
            self.assertFalse(self.operator._configure_posthog_mcp_analytics())
        self.assertIsNone(self.operator._POSTHOG_MCP_CLIENT)

    def test_private_token_file_is_accepted_and_loose_permissions_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("phc_file_token", encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(
                self.operator._read_posthog_project_token_file(path),
                "phc_file_token",
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "permissions"):
                self.operator._read_posthog_project_token_file(path)

    def test_token_file_whitespace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("phc_file_token\n", encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "whitespace"):
                self.operator._read_posthog_project_token_file(path)

    def test_environment_token_whitespace_fails_open(self) -> None:
        with patch.dict(
            self.operator.os.environ,
            {
                self.operator.POSTHOG_MCP_ANALYTICS_SWITCH_ENV: "1",
                self.operator.POSTHOG_PROJECT_TOKEN_ENV: "phc_test\n",
            },
            clear=False,
        ):
            self.assertFalse(self.operator._configure_posthog_mcp_analytics())
        self.assertIsNone(self.operator._POSTHOG_MCP_CLIENT)

    def test_token_file_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            link = Path(directory) / "token"
            target.write_text("phc_file_token\n", encoding="utf-8")
            target.chmod(0o600)
            link.symlink_to(target)
            with self.assertRaises(OSError):
                self.operator._read_posthog_project_token_file(link)

    def test_token_file_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            alias = Path(directory) / "alias"
            path.write_text("phc_file_token\n", encoding="utf-8")
            path.chmod(0o600)
            alias.hardlink_to(path)
            with self.assertRaisesRegex(RuntimeError, "exactly one hard link"):
                self.operator._read_posthog_project_token_file(path)

    def test_token_file_growth_during_read_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_text("phc_file_token\n", encoding="utf-8")
            path.chmod(0o600)
            real_read = self.operator.os.read
            calls = 0

            def growing_read(descriptor: int, size: int) -> bytes:
                nonlocal calls
                calls += 1
                if calls == 1:
                    return real_read(descriptor, size)
                return b"x"

            with (
                patch.object(self.operator.os, "read", side_effect=growing_read),
                self.assertRaisesRegex(RuntimeError, "grew while being read"),
            ):
                self.operator._read_posthog_project_token_file(path)

    def test_oversized_environment_token_fails_open(self) -> None:
        with patch.dict(
            self.operator.os.environ,
            {
                self.operator.POSTHOG_MCP_ANALYTICS_SWITCH_ENV: "1",
                self.operator.POSTHOG_PROJECT_TOKEN_ENV: "phc_" + ("x" * 600),
            },
            clear=False,
        ):
            self.assertFalse(self.operator._configure_posthog_mcp_analytics())
        self.assertIsNone(self.operator._POSTHOG_MCP_CLIENT)

    def test_main_installs_gate_before_posthog_and_builds_http_afterward(self) -> None:
        calls: list[str] = []
        args = types.SimpleNamespace(
            transport="streamable-http",
            host="127.0.0.1",
            port=18181,
        )
        with (
            patch.object(self.operator, "_parse_args", return_value=args),
            patch.object(
                self.operator,
                "_configure_faulthandler",
                side_effect=lambda: calls.append("faulthandler"),
            ),
            patch.object(
                self.operator.grabowski_flowlines,
                "configure_flowlines_observability",
                side_effect=lambda *_args, **_kwargs: calls.append("flowlines"),
            ),
            patch.object(
                self.operator,
                "_install_deployment_admission_gate",
                side_effect=lambda: calls.append("gate"),
            ),
            patch.object(
                self.operator,
                "_configure_http_runtime",
                side_effect=lambda **kwargs: calls.append(
                    f"http:{kwargs.get('admission_gate_preinstalled')}"
                ),
            ),
            patch.object(
                self.operator,
                "_configure_posthog_mcp_analytics",
                side_effect=lambda: calls.append("posthog"),
            ),
            patch.object(
                self.operator.mcp,
                "run",
                create=True,
                side_effect=lambda **kwargs: calls.append("run"),
            ),
            patch.object(
                self.operator,
                "_shutdown_posthog_mcp_analytics",
                side_effect=lambda: calls.append("shutdown"),
            ),
        ):
            self.operator.main()
        self.assertEqual(
            calls,
            [
                "faulthandler",
                "flowlines",
                "gate",
                "posthog",
                "http:True",
                "run",
                "shutdown",
            ],
        )

    def test_main_keeps_loop_bound_analytics_wrapper_off_sync_worker_loops(self) -> None:
        args = types.SimpleNamespace(
            transport="streamable-http",
            host="127.0.0.1",
            port=18181,
        )
        analytics_lock = asyncio.Lock()

        def install_posthog_like_wrapper() -> bool:
            original = self.operator.mcp._tool_manager.call_tool

            async def wrapped(*call_args, **call_kwargs):
                async with analytics_lock:
                    # Force overlap so the historical ordering would move one
                    # shared loop-bound lock into multiple asyncio.run() workers.
                    await asyncio.sleep(0.05)
                    return await original(*call_args, **call_kwargs)

            self.operator.mcp._tool_manager.call_tool = wrapped
            return True

        def exercise_http_transport(**_kwargs) -> None:
            async def run_calls() -> None:
                await asyncio.gather(
                    *(
                        self.operator.mcp._tool_manager.call_tool(
                            "read", {}, context=None
                        )
                        for _ in range(3)
                    )
                )

            asyncio.run(run_calls())

        with (
            patch.object(self.operator, "_parse_args", return_value=args),
            patch.object(self.operator, "_configure_faulthandler"),
            patch.object(
                self.operator.grabowski_flowlines,
                "configure_flowlines_observability",
                return_value={"installed": True},
            ),
            patch.object(
                self.operator,
                "_configure_posthog_mcp_analytics",
                side_effect=install_posthog_like_wrapper,
            ),
            patch.object(
                self.operator,
                "_shutdown_posthog_mcp_analytics",
            ),
            patch.object(
                self.operator.mcp,
                "run",
                create=True,
                side_effect=exercise_http_transport,
            ),
        ):
            self.operator.main()

    def test_http_runtime_failure_still_shuts_down_posthog(self) -> None:
        calls: list[str] = []
        args = types.SimpleNamespace(
            transport="streamable-http",
            host="127.0.0.1",
            port=18181,
        )
        with (
            patch.object(self.operator, "_parse_args", return_value=args),
            patch.object(self.operator, "_configure_faulthandler"),
            patch.object(
                self.operator.grabowski_flowlines,
                "configure_flowlines_observability",
                side_effect=lambda *_args, **_kwargs: calls.append("flowlines"),
            ),
            patch.object(
                self.operator,
                "_install_deployment_admission_gate",
                side_effect=lambda: calls.append("gate"),
            ),
            patch.object(
                self.operator,
                "_configure_posthog_mcp_analytics",
                side_effect=lambda: calls.append("posthog"),
            ),
            patch.object(
                self.operator,
                "_configure_http_runtime",
                side_effect=lambda **kwargs: (
                    calls.append(
                        f"http:{kwargs.get('admission_gate_preinstalled')}"
                    ),
                    (_ for _ in ()).throw(RuntimeError("http setup failed")),
                )[-1],
            ),
            patch.object(
                self.operator.mcp,
                "run",
                create=True,
                side_effect=lambda **kwargs: calls.append("run"),
            ),
            patch.object(
                self.operator,
                "_shutdown_posthog_mcp_analytics",
                side_effect=lambda: calls.append("shutdown"),
            ),
            self.assertRaisesRegex(RuntimeError, "http setup failed"),
        ):
            self.operator.main()
        self.assertEqual(
            calls, ["flowlines", "gate", "posthog", "http:True", "shutdown"]
        )

    def test_http_runtime_preserves_preinstalled_gate_inside_later_wrapper(self) -> None:
        self.operator._install_deployment_admission_gate()
        gate = self.operator.mcp._tool_manager.call_tool

        async def later_wrapper(*args, **kwargs):
            return await gate(*args, **kwargs)

        self.operator.mcp._tool_manager.call_tool = later_wrapper
        self.operator._configure_http_runtime(admission_gate_preinstalled=True)
        self.assertIs(self.operator.mcp._tool_manager.call_tool, later_wrapper)

    def test_http_runtime_requires_claimed_preinstalled_gate(self) -> None:
        with patch.object(
            self.operator,
            "_DEPLOYMENT_ADMISSION_GATE_INSTALLED",
            False,
        ):
            with self.assertRaisesRegex(
                RuntimeError, "deployment admission gate was not preinstalled"
            ):
                self.operator._configure_http_runtime(
                    admission_gate_preinstalled=True
                )

    def test_enabled_configuration_disables_schema_and_payload_capture(self) -> None:
        calls: dict[str, object] = {}

        class FakePosthog:
            def __init__(self, token: str, *, host: str):
                calls["token"] = token
                calls["host"] = host
                self.shutdown_calls = 0

            def shutdown(self) -> None:
                self.shutdown_calls += 1
                calls["shutdown_calls"] = self.shutdown_calls

        class FakeOptions:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)
                calls["options"] = kwargs

        def instrument(server, client, options):
            calls["server"] = server
            calls["client"] = client
            calls["instrument_options"] = options
            return object()

        posthog = types.ModuleType("posthog")
        posthog.__path__ = []
        posthog.Posthog = FakePosthog
        posthog_mcp = types.ModuleType("posthog.mcp")
        posthog_mcp.__path__ = []
        posthog_mcp.instrument = instrument
        posthog_types = types.ModuleType("posthog.mcp.types")
        posthog_types.MCPAnalyticsOptions = FakeOptions
        posthog.mcp = posthog_mcp
        posthog_mcp.types = posthog_types

        with (
            patch.dict(
                sys.modules,
                {
                    "posthog": posthog,
                    "posthog.mcp": posthog_mcp,
                    "posthog.mcp.types": posthog_types,
                },
                clear=False,
            ),
            patch.dict(
                self.operator.os.environ,
                {
                    self.operator.POSTHOG_MCP_ANALYTICS_SWITCH_ENV: "1",
                    self.operator.POSTHOG_PROJECT_TOKEN_ENV: "phc_test",
                    self.operator.POSTHOG_HOST_ENV: "https://eu.i.posthog.com",
                },
                clear=False,
            ),
        ):
            self.assertTrue(self.operator._configure_posthog_mcp_analytics())

        options = calls["options"]
        assert isinstance(options, dict)
        self.assertFalse(options["report_missing"])
        self.assertFalse(options["enable_conversation_id"])
        self.assertFalse(options["enable_exception_autocapture"])
        self.assertFalse(options["context"])
        self.assertFalse(options["capture_model"])
        self.assertFalse(options["collect_feedback"])
        self.assertIs(
            options["before_send"],
            self.operator._posthog_metadata_only_before_send,
        )
        self.assertEqual(calls["host"], "https://eu.i.posthog.com")
        self.operator._shutdown_posthog_mcp_analytics()
        self.assertEqual(calls["shutdown_calls"], 1)
        self.assertIsNone(self.operator._POSTHOG_MCP_CLIENT)

    def test_explicit_disable_means_no_behavior_change(self) -> None:
        with patch.dict(
            self.operator.os.environ,
            {
                self.operator.POSTHOG_MCP_ANALYTICS_SWITCH_ENV: "0",
                self.operator.POSTHOG_PROJECT_TOKEN_ENV: "phc_should_not_be_used",
            },
            clear=False,
        ):
            self.assertFalse(self.operator._configure_posthog_mcp_analytics())
        self.assertIsNone(self.operator._POSTHOG_MCP_CLIENT)


if __name__ == "__main__":
    unittest.main()
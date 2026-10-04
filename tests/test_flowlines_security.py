from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_flowlines as flowlines


EXPECTED_OTLP_AUTH_ENV = frozenset(
    {
        "OTEL_EXPORTER_OTLP_HEADERS",
        "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
        "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "OTEL_PYTHON_EXPORTER_OTLP_HTTP_CREDENTIAL_PROVIDER",
        "OTEL_PYTHON_EXPORTER_OTLP_HTTP_TRACES_CREDENTIAL_PROVIDER",
        "OTEL_PYTHON_EXPORTER_OTLP_HTTP_METRICS_CREDENTIAL_PROVIDER",
        "OTEL_PYTHON_EXPORTER_OTLP_HTTP_LOGS_CREDENTIAL_PROVIDER",
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_METRICS_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_TRACES_CLIENT_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE",
        "OTEL_EXPORTER_OTLP_CLIENT_KEY",
        "OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY",
        "OTEL_EXPORTER_OTLP_METRICS_CLIENT_KEY",
        "OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY",
    }
)
EXPECTED_CHILD_OTLP_ENV = EXPECTED_OTLP_AUTH_ENV | frozenset(
    {
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
        "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
    }
)


class FlowlinesSecurityRegressionTests(unittest.TestCase):
    def test_posthog_token_is_redacted_in_all_flowlines_text_surfaces(self) -> None:
        token = "ph" + "c_" + ("P" * 32)
        for value in (
            f"reason {token}",
            f"user intent {token}",
            token,
            f"session-{token}",
            f"request-{token}",
        ):
            with self.subTest(value=value):
                redacted = flowlines._redact_sensitive_text(value)
                self.assertNotIn(token, redacted)
                self.assertIn("<REDACTED_POSTHOG_TOKEN>", redacted)

        recursive = flowlines._redact_sensitive_arguments(
            {
                "outcome_summary": f"rotated {token}",
                "unmet_needs": [
                    f"remove {token}",
                    {"nested": f"credential {token}"},
                ],
            }
        )
        serialized = json.dumps(recursive, sort_keys=True)
        self.assertNotIn(token, serialized)
        self.assertIn("<REDACTED_POSTHOG_TOKEN>", serialized)

    def test_flowlines_does_not_make_operator_nondumpable(self) -> None:
        source = (SRC / "grabowski_flowlines.py").read_text(encoding="utf-8")
        self.assertNotIn("PR_SET_DUMPABLE", source)
        self.assertNotIn("_ensure_process_nondumpable", source)

    def test_secure_credential_loader_accepts_only_exact_rootbroker_header(self) -> None:
        cases = (
            (None, None),
            ("", None),
            ("not-a-flowlines-header", None),
            ("x-flowlines-api-key=", None),
            ("x-flowlines-api-key=one,x-flowlines-api-key=two", None),
            ("x-flowlines-api-key=one,authorization=two", None),
            ("x-flowlines-api-key=fixture-flowlines-key", "fixture-flowlines-key"),
        )
        for returned, expected in cases:
            with (
                self.subTest(returned=returned),
                mock.patch.object(
                    flowlines,
                    "_read_flowlines_headers_from_rootbroker",
                    return_value=returned,
                    create=True,
                ),
            ):
                self.assertEqual(flowlines._load_flowlines_api_key(), expected)

    def test_environment_header_is_discarded_not_used_as_flowlines_credential(self) -> None:
        header = "x-flowlines-api-key=fixture-environment-secret"
        with (
            mock.patch.dict(
                os.environ,
                {
                    "GRABOWSKI_FLOWLINES_ENABLED": "1",
                    "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
                    "OTEL_EXPORTER_OTLP_HEADERS": header,
                },
                clear=True,
            ),
            mock.patch.object(
                flowlines,
                "_read_flowlines_headers_from_rootbroker",
                return_value=None,
                create=True,
            ),
        ):
            tracer, provider = flowlines._build_environment_tracer()
            self.assertIsNone(tracer)
            self.assertIsNone(provider)
            self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS", os.environ)

    def test_flowlines_endpoint_defaults_to_internal_pinned_origin(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(flowlines._endpoint_is_flowlines())

    def test_flowlines_endpoint_rejects_userinfo_query_fragment_and_wrong_path(self) -> None:
        cases = (
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://u:p@api.flowlines.ai"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://api.flowlines.ai?a=b"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://api.flowlines.ai#x"),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "https://api.flowlines.ai/v1/traces"),
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "https://u:p@api.flowlines.ai/v1/traces",
            ),
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "https://api.flowlines.ai/v1/traces?a=b",
            ),
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "https://api.flowlines.ai/v1/traces#x",
            ),
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "https://api.flowlines.ai/traces",
            ),
        )
        for name, value in cases:
            environment = {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
                name: value,
            }
            with self.subTest(name=name, value=value), mock.patch.dict(
                os.environ,
                environment,
                clear=True,
            ):
                self.assertFalse(flowlines._endpoint_is_flowlines())

    def test_safe_trace_endpoint_does_not_mask_unsafe_generic_endpoint(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://u:p@api.flowlines.ai",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://api.flowlines.ai/v1/traces",
            },
            clear=True,
        ):
            self.assertFalse(flowlines._endpoint_is_flowlines())

    def test_flowlines_endpoint_variables_are_consumed_when_export_is_rejected(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "GRABOWSKI_FLOWLINES_ENABLED": "1",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": (
                    "https://api.flowlines.ai/v1/traces?a=b"
                ),
            },
            clear=True,
        ):
            tracer, provider = flowlines._build_environment_tracer()
            self.assertNotIn("OTEL_EXPORTER_OTLP_ENDPOINT", os.environ)
            self.assertNotIn("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", os.environ)

        self.assertIsNone(tracer)
        self.assertIsNone(provider)

    def test_rootbroker_reader_uses_fixed_secret_free_mainpid_power_request(self) -> None:
        secret = "fixture-flowlines-key"
        header = f"x-flowlines-api-key={secret}"

        class FakeSocket:
            def __init__(self) -> None:
                self.connected: str | None = None
                self.sent = b""
                self.responses: list[bytes] = []
                self.inheritable: bool | None = None
                self.exited = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.exited = True
                return False

            def settimeout(self, _timeout: float) -> None:
                pass

            def set_inheritable(self, inheritable: bool) -> None:
                self.inheritable = inheritable

            def connect(self, path: str) -> None:
                self.connected = path

            def sendall(self, payload: bytes) -> None:
                self.sent = payload
                reference = json.loads(payload.decode("utf-8"))
                self.responses = [
                    json.dumps(
                        {
                            "request_id": reference["request_id"],
                            "action": "operator_power_argv",
                            "mode": "argv-json",
                            "returncode": 0,
                            "timed_out": False,
                            "stdout": header,
                            "stderr": "",
                            "output_evidence": None,
                            "output_evidence_status": "not-applicable",
                        },
                        sort_keys=True,
                    ).encode("utf-8"),
                    b"",
                ]

            def shutdown(self, _how: int) -> None:
                pass

            def recv(self, _size: int) -> bytes:
                return self.responses.pop(0)

        fake = FakeSocket()
        with mock.patch.object(
            flowlines.socket,
            "socket",
            return_value=fake,
        ):
            observed = flowlines._read_flowlines_headers_from_rootbroker()

        self.assertEqual(observed, header)
        self.assertEqual(fake.connected, "/run/grabowski/privileged-broker.sock")
        self.assertFalse(fake.inheritable)
        self.assertTrue(fake.exited)
        request_text = fake.sent.decode("utf-8")
        self.assertNotIn(secret, request_text)
        reference = json.loads(request_text)
        self.assertEqual(reference["action"], "operator_power_argv")
        target = json.loads(reference["target"])
        self.assertEqual(target["argv"][:2], ["/usr/bin/python3", "-c"])
        self.assertEqual(target["cwd"], "/")
        self.assertEqual(target["timeout_seconds"], 5)
        self.assertEqual(len(target["argv"]), 3)
        script = target["argv"][2]
        self.assertIn("/etc/grabowski/flowlines-headers", script)
        self.assertIn("O_NOFOLLOW", script)
        self.assertIn("st_uid == 0", script)
        self.assertIn("0o600", script)
        self.assertNotIn(secret, script)

    def test_service_keeps_flowlines_explicitly_opt_in_and_secret_free(self) -> None:
        service = (
            ROOT / "systemd" / "grabowski-operator.service.example"
        ).read_text(encoding="utf-8")
        dropin = (
            ROOT
            / "systemd"
            / "grabowski-operator.service.d"
            / "80-flowlines.conf.example"
        ).read_text(encoding="utf-8")

        self.assertNotIn("flowlines.env", service)
        self.assertNotIn("flowlines-enabled.env", service)
        self.assertNotIn("Environment=GRABOWSKI_FLOWLINES_ENABLED=1", service)
        self.assertNotIn("Environment=OTEL_EXPORTER_OTLP_ENDPOINT=", service)
        self.assertNotIn("Environment=OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=", service)
        unset_line = next(
            line for line in service.splitlines() if line.startswith("UnsetEnvironment=")
        )
        self.assertEqual(
            frozenset(unset_line.removeprefix("UnsetEnvironment=").split()),
            EXPECTED_CHILD_OTLP_ENV,
        )
        self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS=", service)
        self.assertNotIn("OTEL_EXPORTER_OTLP_TRACES_HEADERS=", service)

        self.assertNotIn("Environment=GRABOWSKI_FLOWLINES_ENABLED=1", dropin)
        self.assertIn(
            "EnvironmentFile=-/etc/grabowski/flowlines-enabled.env",
            dropin,
        )
        self.assertIn("/etc/grabowski/flowlines-headers", dropin)
        self.assertNotIn("OTEL_EXPORTER_OTLP_ENDPOINT=", dropin)
        self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS=", dropin)

    def test_standalone_entrypoint_does_not_load_environment_exporter(self) -> None:
        source = (SRC / "grabowski_mcp.py").read_text(encoding="utf-8")
        main_block = source.split('if __name__ == "__main__":', 1)[1]
        self.assertIn("configure_flowlines_observability(", main_block)
        self.assertIn("load_environment_exporter=False", main_block)

    def test_all_forbidden_otlp_auth_variables_are_consumed(self) -> None:
        self.assertEqual(
            frozenset(flowlines._FLOWLINES_FORBIDDEN_EXPORT_ENV),
            EXPECTED_OTLP_AUTH_ENV,
        )
        environment = {
            "GRABOWSKI_FLOWLINES_ENABLED": "0",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "https://api.flowlines.ai",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://api.flowlines.ai/v1/traces",
        }
        environment.update({key: "fixture-secret" for key in EXPECTED_OTLP_AUTH_ENV})
        with mock.patch.dict(os.environ, environment, clear=True):
            tracer, provider = flowlines._build_environment_tracer()
            self.assertIsNone(tracer)
            self.assertIsNone(provider)
            for key in EXPECTED_OTLP_AUTH_ENV:
                self.assertNotIn(key, os.environ)

    def test_verified_flowlines_identity_fallback_is_local_only(self) -> None:
        import grabowski_mcp

        local_context = SimpleNamespace(request=None)
        transport_context = SimpleNamespace(request=SimpleNamespace(headers={}))

        self.assertIsNone(grabowski_mcp._flowlines_verified_identity(local_context))
        with self.assertRaisesRegex(RuntimeError, "enrolled connector identity"):
            grabowski_mcp._flowlines_verified_identity(transport_context)

    def test_production_entrypoints_bind_verified_flowlines_identity(self) -> None:
        operator = (SRC / "grabowski_operator.py").read_text(encoding="utf-8")
        runtime = (SRC / "grabowski_runtime.py").read_text(encoding="utf-8")
        self.assertIn("verified_identity_resolver=base._flowlines_verified_identity", operator)
        self.assertIn("verified_identity_resolver=grabowski_mcp._flowlines_verified_identity", runtime)

    def test_child_boundaries_strip_full_otlp_auth_surface(self) -> None:
        import grabowski_agent_sandbox as sandbox
        import grabowski_mcp

        operator = (SRC / "grabowski_operator.py").read_text(encoding="utf-8")
        service = (
            ROOT / "systemd" / "grabowski-operator.service.example"
        ).read_text(encoding="utf-8")

        self.assertTrue(
            EXPECTED_CHILD_OTLP_ENV.issubset(grabowski_mcp.SERVER_ONLY_CHILD_ENV_KEYS)
        )
        parent = {key: "fixture-secret" for key in EXPECTED_CHILD_OTLP_ENV}
        with mock.patch.dict(os.environ, parent, clear=True):
            mcp_child = grabowski_mcp._server_child_environment()
        sandbox_child = sandbox.safe_git_environment(parent)

        for key in EXPECTED_CHILD_OTLP_ENV:
            with self.subTest(key=key):
                self.assertIn(key, operator)
                self.assertIn(key, service)
                self.assertNotIn(key, mcp_child)
                self.assertNotIn(key, sandbox_child)


if __name__ == "__main__":
    unittest.main()

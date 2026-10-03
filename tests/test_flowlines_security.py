from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_flowlines as flowlines


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

    def test_process_nondumpable_contract_requires_set_and_readback(self) -> None:
        with mock.patch.object(
            flowlines,
            "_linux_prctl",
            side_effect=[0, 0],
            create=True,
        ) as prctl:
            self.assertTrue(flowlines._ensure_process_nondumpable())
        self.assertEqual(
            prctl.call_args_list,
            [mock.call(4, 0), mock.call(3, 0)],
        )

        with mock.patch.object(
            flowlines,
            "_linux_prctl",
            side_effect=[0, 1],
            create=True,
        ):
            self.assertFalse(flowlines._ensure_process_nondumpable())

    def test_secure_credential_loader_requires_hardening_and_rootbroker(self) -> None:
        with mock.patch.object(
            flowlines,
            "_ensure_process_nondumpable",
            return_value=False,
            create=True,
        ):
            with self.assertRaisesRegex(RuntimeError, "nondumpable"):
                flowlines._load_flowlines_api_key()

        with (
            mock.patch.object(
                flowlines,
                "_ensure_process_nondumpable",
                return_value=True,
                create=True,
            ),
            mock.patch.object(
                flowlines,
                "_read_flowlines_headers_from_rootbroker",
                return_value="x-flowlines-api-key=fixture-flowlines-key",
                create=True,
            ) as read_secret,
        ):
            self.assertEqual(
                flowlines._load_flowlines_api_key(),
                "fixture-flowlines-key",
            )
        read_secret.assert_called_once_with()

    def test_secure_credential_loader_rejects_missing_or_malformed_broker_data(self) -> None:
        for returned in (
            None,
            "",
            "not-a-flowlines-header",
            "x-flowlines-api-key=",
            "x-flowlines-api-key=one,x-flowlines-api-key=two",
            "x-flowlines-api-key=one,authorization=two",
        ):
            with (
                self.subTest(returned=returned),
                mock.patch.object(
                    flowlines,
                    "_ensure_process_nondumpable",
                    return_value=True,
                    create=True,
                ),
                mock.patch.object(
                    flowlines,
                    "_read_flowlines_headers_from_rootbroker",
                    return_value=returned,
                    create=True,
                ),
            ):
                self.assertIsNone(flowlines._load_flowlines_api_key())

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
                "_ensure_process_nondumpable",
                return_value=True,
                create=True,
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
        self.assertNotIn(
            "EnvironmentFile=-/home/alex/.config/grabowski/flowlines.env",
            service,
        )
        self.assertNotIn("Environment=GRABOWSKI_FLOWLINES_ENABLED=1", service)
        self.assertIn(
            "EnvironmentFile=-/home/alex/.config/grabowski/flowlines-enabled.env",
            service,
        )
        self.assertIn(
            "UnsetEnvironment=OTEL_EXPORTER_OTLP_HEADERS OTEL_EXPORTER_OTLP_TRACES_HEADERS",
            service,
        )
        self.assertNotIn("OTEL_EXPORTER_OTLP_HEADERS=", service)
        self.assertNotIn("OTEL_EXPORTER_OTLP_TRACES_HEADERS=", service)


if __name__ == "__main__":
    unittest.main()

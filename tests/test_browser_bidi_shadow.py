from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from tools import browser_bidi_shadow_benchmark_core as shadow


class BrowserBidiShadowContractTests(unittest.TestCase):
    def test_geckodriver_argv_is_loopback_only(self) -> None:
        argv = shadow.build_geckodriver_argv(
            geckodriver=Path("/tmp/geckodriver"),
            firefox=Path("/usr/bin/firefox"),
            http_port=4445,
            websocket_port=9502,
            profile_root=Path("/tmp/profiles"),
        )
        self.assertEqual(argv[1:3], ["--host", "127.0.0.1"])
        self.assertEqual(argv[3:5], ["--port", "4445"])
        self.assertEqual(argv[5:7], ["--websocket-port", "9502"])
        self.assertIn("/usr/bin/firefox", argv)

    def test_geckodriver_argv_rejects_shared_port(self) -> None:
        with self.assertRaisesRegex(shadow.BidiShadowError, "must differ"):
            shadow.build_geckodriver_argv(
                geckodriver=Path("/tmp/geckodriver"),
                firefox=Path("/usr/bin/firefox"),
                http_port=4445,
                websocket_port=4445,
                profile_root=Path("/tmp/profiles"),
            )

    def test_geckodriver_argv_rejects_privileged_port(self) -> None:
        with self.assertRaisesRegex(shadow.BidiShadowError, "allowed range"):
            shadow.build_geckodriver_argv(
                geckodriver=Path("/tmp/geckodriver"),
                firefox=Path("/usr/bin/firefox"),
                http_port=80,
                websocket_port=9502,
                profile_root=Path("/tmp/profiles"),
            )

    def test_session_payload_requests_bidi_without_changing_browser_family(self) -> None:
        payload = shadow.build_session_payload()
        always = payload["capabilities"]["alwaysMatch"]
        self.assertEqual(always["browserName"], "firefox")
        self.assertIs(always["webSocketUrl"], True)
        self.assertEqual(always["moz:firefoxOptions"]["args"], ["-headless"])

    def test_strict_loopback_websocket_binding_accepts_expected_session(self) -> None:
        value = "ws://127.0.0.1:9502/session/session-1"
        self.assertEqual(
            shadow.validate_loopback_ws_url(
                value, expected_session_id="session-1", expected_port=9502
            ),
            value,
        )

    def test_strict_loopback_websocket_binding_rejects_non_loopback(self) -> None:
        with self.assertRaisesRegex(shadow.BidiShadowError, "strict loopback"):
            shadow.validate_loopback_ws_url(
                "ws://192.168.178.55:9502/session/session-1",
                expected_session_id="session-1",
                expected_port=9502,
            )

    def test_strict_loopback_websocket_binding_rejects_wrong_session(self) -> None:
        with self.assertRaisesRegex(shadow.BidiShadowError, "session path"):
            shadow.validate_loopback_ws_url(
                "ws://127.0.0.1:9502/session/other",
                expected_session_id="session-1",
                expected_port=9502,
            )

    def test_strict_loopback_websocket_binding_rejects_query(self) -> None:
        with self.assertRaisesRegex(shadow.BidiShadowError, "strict loopback"):
            shadow.validate_loopback_ws_url(
                "ws://127.0.0.1:9502/session/session-1?token=x",
                expected_session_id="session-1",
                expected_port=9502,
            )

    def test_parse_session_response_binds_versions_and_socket(self) -> None:
        result = shadow.parse_session_response(
            {
                "value": {
                    "sessionId": "session-1",
                    "capabilities": {
                        "browserVersion": "153.0",
                        "moz:geckodriverVersion": "0.37.1",
                        "webSocketUrl": "ws://127.0.0.1:9502/session/session-1",
                    },
                }
            },
            expected_websocket_port=9502,
        )
        self.assertEqual(result["session_id"], "session-1")
        self.assertEqual(result["browser_version"], "153.0")
        self.assertEqual(result["geckodriver_version"], "0.37.1")

    def test_semantic_parity_is_exact_for_ready_state_and_elements(self) -> None:
        parity = shadow.compare_semantics(
            shadow.DEFAULT_REFERENCE,
            {
                "readyState": "complete",
                "elements": [{"role": "button", "name": "Wave B semantic target"}],
            },
        )
        self.assertTrue(parity["matched"])
        self.assertEqual(parity["mismatches"], [])
        self.assertEqual(parity["reference_sha256"], parity["observed_sha256"])

    def test_semantic_parity_reports_element_mismatch(self) -> None:
        parity = shadow.compare_semantics(
            shadow.DEFAULT_REFERENCE,
            {
                "readyState": "complete",
                "elements": [{"role": "button", "name": "different"}],
            },
        )
        self.assertFalse(parity["matched"])
        self.assertEqual(parity["mismatches"], ["elements"])

    def test_webdriver_http_error_keeps_bounded_error_and_message(self) -> None:
        response = mock.Mock(status=500)
        response.read.return_value = json.dumps(
            {
                "value": {
                    "error": "unknown error",
                    "message": "Process unexpectedly closed",
                    "stacktrace": "must not be surfaced",
                }
            }
        ).encode("utf-8")
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            shadow.http.client, "HTTPConnection", return_value=connection
        ):
            with self.assertRaisesRegex(
                shadow.BidiShadowError,
                "status 500: unknown error - Process unexpectedly closed",
            ) as raised:
                shadow._http_json("POST", 4445, "/session", payload={})
        self.assertNotIn("stacktrace", str(raised.exception))
        connection.close.assert_called_once_with()

    def test_server_websocket_frame_must_not_be_masked(self) -> None:
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        right.sendall(bytes([0x81, 0x80]))
        with self.assertRaisesRegex(shadow.BidiShadowError, "invalid masked"):
            shadow._recv_frame(left)

    def test_bidi_connection_rejects_non_loopback_before_connect(self) -> None:
        with self.assertRaisesRegex(shadow.BidiShadowError, "not loopback"):
            with shadow.BidiJsonConnection("ws://example.com:9502/session/x"):
                pass

    def test_failure_report_never_grants_retry_or_cutover(self) -> None:
        report = shadow.failure_report(shadow.BidiShadowError("boom"))
        self.assertEqual(report["state"], "failed_closed")
        self.assertIs(report["production_adapter_changed"], False)
        self.assertIs(report["retry_authorized"], False)
        self.assertIn("permission_to_replace_chrome_cdp", report["does_not_establish"])
        self.assertIn("resource_lease_ownership", report["does_not_establish"])


class BrowserBidiShadowRunTests(unittest.TestCase):
    def _executable(self, root: Path, name: str) -> Path:
        path = root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o700)
        return path

    def test_run_returns_shadow_parity_without_production_cutover(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            geckodriver = self._executable(root, "geckodriver")
            firefox = self._executable(root, "firefox")

            process = mock.Mock()
            process.poll.return_value = None
            process.wait.return_value = 0

            session_document = {
                "value": {
                    "sessionId": "session-1",
                    "capabilities": {
                        "browserVersion": "153.0",
                        "moz:geckodriverVersion": "0.37.1",
                        "webSocketUrl": "ws://127.0.0.1:9502/session/session-1",
                    },
                }
            }

            class FakeBidi:
                def __init__(self, _url: str) -> None:
                    self.calls: list[str] = []

                def __enter__(self) -> "FakeBidi":
                    return self

                def __exit__(self, *_args: object) -> None:
                    return None

                def call(self, method: str, params: dict[str, object]):
                    self.calls.append(method)
                    if method == "browsingContext.getTree":
                        return (
                            {
                                "result": {
                                    "contexts": [{"context": "context-1"}]
                                }
                            },
                            1.0,
                        )
                    if method == "browsingContext.navigate":
                        return ({"result": {"url": params["url"]}}, 2.0)
                    if method == "script.evaluate":
                        value = json.dumps(
                            {
                                "readyState": "complete",
                                "elements": [
                                    {
                                        "role": "button",
                                        "name": "Wave B semantic target",
                                    }
                                ],
                            }
                        )
                        return (
                            {
                                "result": {
                                    "result": {"type": "string", "value": value}
                                }
                            },
                            3.0,
                        )
                    raise AssertionError(method)

            http_calls: list[tuple[str, str]] = []

            def fake_http(method: str, _port: int, path: str, **_kwargs: object):
                http_calls.append((method, path))
                if method == "POST" and path == "/session":
                    return session_document
                if method == "DELETE" and path == "/session/session-1":
                    return {"value": None}
                raise AssertionError((method, path))

            with (
                mock.patch.object(shadow.subprocess, "Popen", return_value=process),
                mock.patch.object(shadow, "_wait_for_driver"),
                mock.patch.object(shadow, "_http_json", side_effect=fake_http),
                mock.patch.object(shadow, "BidiJsonConnection", FakeBidi),
                mock.patch.object(shadow, "_terminate_process_group") as terminate_group,
            ):
                report = shadow.run_shadow_benchmark(
                    geckodriver=geckodriver,
                    firefox=firefox,
                    http_port=4445,
                    websocket_port=9502,
                    work_root=root,
                )

        self.assertEqual(report["state"], "passed")
        self.assertEqual(report["transport"], "webdriver-bidi")
        self.assertIs(report["production_adapter_changed"], False)
        self.assertIs(report["retry_authorized"], False)
        self.assertTrue(report["parity"]["matched"])
        self.assertIn("resource_lease_ownership", report["does_not_establish"])
        self.assertEqual(report["timings_ms"]["get_tree_ms"], 1.0)
        self.assertEqual(report["timings_ms"]["navigate_ms"], 2.0)
        self.assertEqual(report["timings_ms"]["evaluate_ms"], 3.0)
        self.assertIn(("DELETE", "/session/session-1"), http_calls)
        terminate_group.assert_called_once_with(process)

    def test_process_group_cleanup_terminates_the_owned_group(self) -> None:
        process = mock.Mock(pid=12345)
        process.poll.return_value = None
        process.wait.return_value = 0
        with mock.patch.object(shadow.os, "killpg") as killpg:
            shadow._terminate_process_group(process)
        killpg.assert_called_once_with(12345, shadow.signal.SIGTERM)

    def test_process_group_cleanup_escalates_after_grace_timeout(self) -> None:
        process = mock.Mock(pid=12345)
        process.poll.return_value = None
        process.wait.side_effect = [shadow.subprocess.TimeoutExpired("driver", 3), 0]
        with mock.patch.object(shadow.os, "killpg") as killpg:
            shadow._terminate_process_group(process)
        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(12345, shadow.signal.SIGTERM),
                mock.call(12345, shadow.signal.SIGKILL),
            ],
        )

    def test_run_rejects_unavailable_executable_before_process_start(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            with self.assertRaisesRegex(shadow.BidiShadowError, "geckodriver"):
                shadow.run_shadow_benchmark(
                    geckodriver=root / "missing",
                    firefox=Path("/usr/bin/firefox"),
                    http_port=4445,
                    websocket_port=9502,
                    work_root=root,
                )


if __name__ == "__main__":
    unittest.main()

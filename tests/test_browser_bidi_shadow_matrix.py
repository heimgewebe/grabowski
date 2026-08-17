from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from tools import browser_bidi_shadow_matrix as matrix


class BrowserBidiShadowMatrixContractTests(unittest.TestCase):
    def test_chromedriver_argv_is_loopback_restricted(self) -> None:
        argv = matrix.build_chromedriver_argv(
            chromedriver=Path('/tmp/chromedriver'), http_port=9515
        )
        self.assertEqual(argv[1], '--port=9515')
        self.assertIn('--allowed-ips=127.0.0.1', argv)

    def test_chromedriver_argv_rejects_privileged_port(self) -> None:
        with self.assertRaisesRegex(matrix.shadow.BidiShadowError, 'allowed range'):
            matrix.build_chromedriver_argv(
                chromedriver=Path('/tmp/chromedriver'), http_port=80
            )

    def test_chrome_payload_uses_only_explicit_binary_and_temporary_profile(self) -> None:
        payload = matrix.build_chrome_session_payload(
            chrome=Path('/opt/google/chrome/google-chrome'),
            profile=Path('/tmp/matrix/profile'),
        )
        always = payload['capabilities']['alwaysMatch']
        self.assertEqual(always['browserName'], 'chrome')
        self.assertIs(always['webSocketUrl'], True)
        options = always['goog:chromeOptions']
        self.assertEqual(options['binary'], '/opt/google/chrome/google-chrome')
        self.assertIn('--user-data-dir=/tmp/matrix/profile', options['args'])

    def test_chrome_payload_rejects_relative_profile(self) -> None:
        with self.assertRaisesRegex(matrix.shadow.BidiShadowError, 'absolute'):
            matrix.build_chrome_session_payload(
                chrome=Path('/opt/google/chrome/google-chrome'),
                profile=Path('relative/profile'),
            )

    def test_chrome_websocket_accepts_localhost_only_after_ipv4_loopback_resolution(self) -> None:
        with mock.patch.object(
            matrix.socket,
            'getaddrinfo',
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 9222))],
        ):
            safe = matrix.validate_chrome_loopback_ws_url(
                'ws://localhost:9222/session/session-1', expected_session_id='session-1'
            )
        self.assertEqual(safe, 'ws://127.0.0.1:9222/session/session-1')

    def test_chrome_websocket_rejects_non_loopback_resolution(self) -> None:
        with mock.patch.object(
            matrix.socket,
            'getaddrinfo',
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.10', 9222))],
        ):
            with self.assertRaisesRegex(matrix.shadow.BidiShadowError, 'strictly to IPv4 loopback'):
                matrix.validate_chrome_loopback_ws_url(
                    'ws://localhost:9222/session/session-1', expected_session_id='session-1'
                )

    def test_chrome_websocket_rejects_wrong_session(self) -> None:
        with self.assertRaisesRegex(matrix.shadow.BidiShadowError, 'session path'):
            matrix.validate_chrome_loopback_ws_url(
                'ws://127.0.0.1:9222/session/other', expected_session_id='session-1'
            )

    def test_parse_chrome_session_binds_browser_driver_and_socket(self) -> None:
        document = {
            'value': {
                'sessionId': 'session-1',
                'capabilities': {
                    'browserVersion': '151.0.7922.108',
                    'webSocketUrl': 'ws://127.0.0.1:9222/session/session-1',
                    'chrome': {'chromedriverVersion': '151.0.7922.108 (abcdef)'},
                },
            }
        }
        with mock.patch.object(
            matrix.socket,
            'getaddrinfo',
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 9222))],
        ):
            result = matrix.parse_chrome_session_response(document)
        self.assertEqual(result['browser_version'], '151.0.7922.108')
        self.assertEqual(result['chromedriver_version'], '151.0.7922.108')
        self.assertEqual(result['websocket_url'], 'ws://127.0.0.1:9222/session/session-1')

    def test_matrix_repetition_bound_is_fail_closed(self) -> None:
        with self.assertRaisesRegex(matrix.shadow.BidiShadowError, 'repetitions'):
            matrix.run_shadow_matrix(
                chromedriver=Path('/tmp/chromedriver'),
                chrome=Path('/tmp/chrome'),
                geckodriver=Path('/tmp/geckodriver'),
                firefox=Path('/tmp/firefox'),
                chrome_http_port=9515,
                firefox_http_port=4445,
                firefox_websocket_port=9502,
                work_root=Path('/tmp'),
                reference=matrix.shadow.DEFAULT_REFERENCE,
                repetitions=matrix.MAX_REPETITIONS + 1,
            )


class BrowserBidiShadowMatrixRunTests(unittest.TestCase):
    def _executable(self, root: Path, name: str) -> Path:
        path = root / name
        path.write_text('#!/bin/sh\nexit 0\n', encoding='utf-8')
        path.chmod(0o700)
        return path

    @staticmethod
    def _report(browser: str, total: float, session: float) -> dict[str, object]:
        return {
            'state': 'passed',
            'browser': {'name': browser, 'version': '1'},
            'driver': {'name': 'driver', 'version': '1'},
            'semantic_observation': matrix.shadow.DEFAULT_REFERENCE,
            'parity': matrix.shadow.compare_semantics(
                matrix.shadow.DEFAULT_REFERENCE, matrix.shadow.DEFAULT_REFERENCE
            ),
            'timings_ms': {'session_create_ms': session},
            'total_ms': total,
        }

    def test_matrix_runs_both_engines_repeatedly_without_ranking(self) -> None:
        chrome_reports = [
            self._report('chrome', 500.0, 300.0),
            self._report('chrome', 450.0, 280.0),
            self._report('chrome', 550.0, 320.0),
        ]
        firefox_reports = [
            self._report('firefox', 1500.0, 1400.0),
            self._report('firefox', 1300.0, 1200.0),
            self._report('firefox', 1700.0, 1600.0),
        ]
        with (
            mock.patch.object(matrix, 'run_chrome_bidi_once', side_effect=chrome_reports) as chrome_run,
            mock.patch.object(
                matrix.shadow, 'run_shadow_benchmark', side_effect=firefox_reports
            ) as firefox_run,
        ):
            report = matrix.run_shadow_matrix(
                chromedriver=Path('/tmp/chromedriver'),
                chrome=Path('/tmp/chrome'),
                geckodriver=Path('/tmp/geckodriver'),
                firefox=Path('/tmp/firefox'),
                chrome_http_port=9515,
                firefox_http_port=4445,
                firefox_websocket_port=9502,
                work_root=Path('/tmp'),
                reference=matrix.shadow.DEFAULT_REFERENCE,
                repetitions=3,
            )
        self.assertEqual(report['state'], 'passed')
        self.assertEqual(chrome_run.call_count, 3)
        self.assertEqual(firefox_run.call_count, 3)
        self.assertEqual(
            report['backends']['chrome_webdriver_bidi']['summary']['total_ms']['median'],
            500.0,
        )
        self.assertEqual(
            report['backends']['firefox_webdriver_bidi']['summary']['total_ms']['median'],
            1500.0,
        )
        self.assertTrue(report['timing_comparison_is_advisory'])
        self.assertNotIn('winner', report)
        self.assertFalse(report['production_adapter_changed'])
        self.assertFalse(report['retry_authorized'])
        self.assertIn('performance_superiority', report['does_not_establish'])
        self.assertEqual(report['reference']['transport'], 'chrome-cdp')
        self.assertEqual(report['reference']['source'], 'caller-supplied')

    def test_chrome_run_cleans_session_and_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            chromedriver = self._executable(root, 'chromedriver')
            chrome = self._executable(root, 'chrome')
            process = mock.Mock(pid=12345)
            process.poll.return_value = None
            process.wait.return_value = 0
            session_document = {
                'value': {
                    'sessionId': 'session-1',
                    'capabilities': {
                        'browserVersion': '151.0.7922.108',
                        'webSocketUrl': 'ws://127.0.0.1:9222/session/session-1',
                        'chrome': {'chromedriverVersion': '151.0.7922.108 (abcdef)'},
                    },
                }
            }
            calls: list[tuple[str, str]] = []

            def fake_http(method: str, _port: int, path: str, **_kwargs: object):
                calls.append((method, path))
                if method == 'POST' and path == '/session':
                    return session_document
                if method == 'DELETE' and path == '/session/session-1':
                    return {'value': None}
                raise AssertionError((method, path))

            class FakeBidi:
                def __init__(self, _url: str) -> None:
                    pass
                def __enter__(self) -> 'FakeBidi':
                    return self
                def __exit__(self, *_args: object) -> None:
                    return None
                def call(self, method: str, params: dict[str, object]):
                    if method == 'browsingContext.getTree':
                        return {'result': {'contexts': [{'context': 'context-1'}]}}, 1.0
                    if method == 'browsingContext.navigate':
                        return {'result': {'url': params['url']}}, 2.0
                    if method == 'script.evaluate':
                        value = json.dumps(
                            {
                                'readyState': 'complete',
                                'elements': [
                                    {'role': 'button', 'name': 'Wave B semantic target'}
                                ],
                            }
                        )
                        return {'result': {'result': {'type': 'string', 'value': value}}}, 3.0
                    raise AssertionError(method)

            with (
                mock.patch.object(matrix.subprocess, 'Popen', return_value=process),
                mock.patch.object(matrix, '_wait_for_driver'),
                mock.patch.object(matrix.shadow, '_http_json', side_effect=fake_http),
                mock.patch.object(matrix.shadow, 'BidiJsonConnection', FakeBidi),
                mock.patch.object(matrix.shadow, '_terminate_process_group') as terminate,
                mock.patch.object(
                    matrix.socket,
                    'getaddrinfo',
                    return_value=[
                        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 9222))
                    ],
                ),
            ):
                report = matrix.run_chrome_bidi_once(
                    chromedriver=chromedriver,
                    chrome=chrome,
                    http_port=9515,
                    work_root=root,
                    reference=matrix.shadow.DEFAULT_REFERENCE,
                )
        self.assertEqual(report['state'], 'passed')
        self.assertIn(('DELETE', '/session/session-1'), calls)
        terminate.assert_called_once_with(process)
        self.assertFalse(report['production_adapter_changed'])
        self.assertFalse(report['retry_authorized'])

    def test_matrix_failure_report_never_grants_promotion_or_retry(self) -> None:
        report = matrix.failure_report(matrix.shadow.BidiShadowError('boom'))
        self.assertEqual(report['state'], 'failed_closed')
        self.assertFalse(report['production_adapter_changed'])
        self.assertFalse(report['retry_authorized'])
        self.assertIn('permission_to_replace_chrome_cdp', report['does_not_establish'])


if __name__ == '__main__':
    unittest.main()

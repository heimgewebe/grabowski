from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "juno" / "juno_ipad_agent_bootstrap.py"
SPEC = importlib.util.spec_from_file_location("juno_ipad_agent_bootstrap", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class _Response:
    def __init__(self, payload: bytes, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def read(self, _limit: int) -> bytes:
        return self.payload


class _Connection:
    def __init__(self, response: _Response | None = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.closed = False

    def request(self, *_args: object, **_kwargs: object) -> None:
        if self.error is not None:
            raise self.error

    def getresponse(self) -> _Response:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


class JunoIpadAgentBootstrapTests(unittest.TestCase):
    def test_probe_once_recognizes_expected_health(self) -> None:
        connection = _Connection(
            _Response(b'{"service":"grabowski-juno-ipad-agent","status":"ok"}')
        )
        with patch.object(bootstrap.http.client, "HTTPConnection", return_value=connection):
            self.assertEqual(
                bootstrap._probe_once(),
                ("healthy", "Juno agent already healthy"),
            )
        self.assertTrue(connection.closed)

    def test_probe_once_treats_connection_refused_as_absent(self) -> None:
        connection = _Connection(error=ConnectionRefusedError())
        with patch.object(bootstrap.http.client, "HTTPConnection", return_value=connection):
            self.assertEqual(bootstrap._probe_once(), ("absent", "connection refused"))
        self.assertTrue(connection.closed)

    def test_probe_once_fails_closed_for_wrong_service(self) -> None:
        connection = _Connection(_Response(b'{"service":"other","status":"ok"}'))
        with patch.object(bootstrap.http.client, "HTTPConnection", return_value=connection):
            state, detail = bootstrap._probe_once()
        self.assertEqual(state, "ambiguous")
        self.assertEqual(detail, "another service owns the canonical port")
        self.assertTrue(connection.closed)

    def test_probe_returns_healthy_without_retry(self) -> None:
        with patch.object(
            bootstrap,
            "_probe_once",
            return_value=("healthy", "Juno agent already healthy"),
        ) as probe_once, patch.object(bootstrap.time, "sleep") as sleep:
            self.assertEqual(
                bootstrap._probe(),
                ("healthy", "Juno agent already healthy"),
            )
        probe_once.assert_called_once_with()
        sleep.assert_not_called()

    def test_probe_retries_only_definite_absence(self) -> None:
        with patch.object(
            bootstrap,
            "_probe_once",
            side_effect=[
                ("absent", "connection refused"),
                ("absent", "connection refused"),
                ("healthy", "Juno agent already healthy"),
            ],
        ) as probe_once, patch.object(bootstrap.time, "sleep") as sleep:
            self.assertEqual(
                bootstrap._probe(),
                ("healthy", "Juno agent already healthy"),
            )
        self.assertEqual(probe_once.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_probe_does_not_retry_ambiguous_failure(self) -> None:
        with patch.object(
            bootstrap,
            "_probe_once",
            return_value=("ambiguous", "health request timed out"),
        ) as probe_once, patch.object(bootstrap.time, "sleep") as sleep:
            self.assertEqual(
                bootstrap._probe(),
                ("ambiguous", "health request timed out"),
            )
        probe_once.assert_called_once_with()
        sleep.assert_not_called()

    def test_main_is_noop_when_agent_is_healthy(self) -> None:
        with patch.object(
            bootstrap,
            "_probe",
            return_value=("healthy", "Juno agent already healthy"),
        ), patch.object(bootstrap, "_run_agent") as run_agent:
            self.assertEqual(bootstrap.main(), 0)
        run_agent.assert_not_called()

    def test_main_starts_agent_only_after_definite_absence(self) -> None:
        with patch.object(
            bootstrap,
            "_probe",
            return_value=("absent", "connection refused"),
        ), patch.object(bootstrap, "_run_agent") as run_agent:
            self.assertEqual(bootstrap.main(), 0)
        run_agent.assert_called_once_with()

    def test_main_fails_closed_on_ambiguous_health(self) -> None:
        with patch.object(
            bootstrap,
            "_probe",
            return_value=("ambiguous", "health request timed out"),
        ), patch.object(bootstrap, "_run_agent") as run_agent:
            self.assertEqual(bootstrap.main(), 2)
        run_agent.assert_not_called()

    def test_run_agent_uses_sibling_main_and_restores_argv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "juno_ipad_agent.py"
            agent.write_text("pass\n", encoding="utf-8")
            original = sys.argv[:]
            agent_main = Mock(return_value=0)
            with patch.object(
                bootstrap.runpy,
                "run_path",
                return_value={"main": agent_main},
            ) as run_path:
                bootstrap._run_agent(agent)
            self.assertEqual(sys.argv, original)
            run_path.assert_called_once_with(
                str(agent),
                run_name="grabowski_juno_ipad_agent_recovery_target",
            )
            agent_main.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()

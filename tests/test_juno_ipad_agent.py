from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
AGENT_PATH = ROOT / "tools/juno/juno_ipad_agent.py"
CLIENT_PATH = ROOT / "tools/juno/juno_job_client.py"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


agent = load_module("test_juno_ipad_agent_module", AGENT_PATH)
client_module = load_module("test_juno_job_client_module", CLIENT_PATH)


class NetworkPolicyTests(unittest.TestCase):
    def test_only_loopback_and_tailscale_sources_are_allowed(self) -> None:
        self.assertTrue(agent.client_address_allowed("127.0.0.1"))
        self.assertTrue(agent.client_address_allowed("::1"))
        self.assertTrue(agent.client_address_allowed("100.68.88.111"))
        self.assertTrue(agent.client_address_allowed("fd7a:115c:a1e0::173a:586f"))
        self.assertFalse(agent.client_address_allowed("192.168.178.55"))
        self.assertFalse(agent.client_address_allowed("8.8.8.8"))
        self.assertFalse(agent.client_address_allowed("not-an-address"))


class AuthenticationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.secret = b"s" * 32
        self.authenticator = agent.RequestAuthenticator(self.secret)

    def test_valid_signature_and_replay_rejection(self) -> None:
        body = b'{"hello":"world"}'
        headers = client_module.signed_headers(
            self.secret,
            "POST",
            "/v1/jobs",
            body,
            timestamp=1_700_000_000,
            nonce="nonce_1234567890123456",
        )
        self.authenticator.verify(
            "POST",
            "/v1/jobs",
            body,
            headers,
            now=1_700_000_000,
        )
        with self.assertRaisesRegex(agent.AuthenticationError, "replayed_nonce"):
            self.authenticator.verify(
                "POST",
                "/v1/jobs",
                body,
                headers,
                now=1_700_000_000,
            )

    def test_body_tampering_is_rejected(self) -> None:
        headers = client_module.signed_headers(
            self.secret,
            "POST",
            "/v1/jobs",
            b"original",
            timestamp=1_700_000_000,
            nonce="nonce_abcdefghijklmnop",
        )
        with self.assertRaisesRegex(agent.AuthenticationError, "body_hash_mismatch"):
            self.authenticator.verify(
                "POST",
                "/v1/jobs",
                b"changed",
                headers,
                now=1_700_000_000,
            )

    def test_stale_timestamp_is_rejected(self) -> None:
        headers = client_module.signed_headers(
            self.secret,
            "GET",
            "/v1/jobs",
            b"",
            timestamp=1_700_000_000,
            nonce="nonce_stale_1234567890",
        )
        with self.assertRaisesRegex(agent.AuthenticationError, "stale_timestamp"):
            self.authenticator.verify(
                "GET",
                "/v1/jobs",
                b"",
                headers,
                now=1_700_000_500,
            )


class AgentStateTests(unittest.TestCase):
    def test_job_executes_and_returns_output_and_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = agent.AgentState(Path(directory), start_worker=False)
            submitted = state.submit_job(
                {
                    "schema_version": 1,
                    "job_id": "job-execution-0001",
                    "code": (
                        "print('hello from job')\n"
                        "GRABOWSKI_RESULT = {\n"
                        "    'answer': 42,\n"
                        "    'workspace_exists': GRABOWSKI_WORKSPACE.exists(),\n"
                        "    'metadata': GRABOWSKI_METADATA,\n"
                        "}\n"
                    ),
                    "timeout_seconds": 5,
                    "metadata": {"purpose": "test"},
                }
            )
            self.assertEqual(submitted["state"], "queued")
            result = state.run_job_now("job-execution-0001")
            self.assertEqual(result["state"], "succeeded")
            self.assertEqual(result["stdout"], "hello from job\n")
            self.assertEqual(result["stderr"], "")
            self.assertEqual(result["result"]["answer"], 42)
            self.assertTrue(result["result"]["workspace_exists"])
            self.assertEqual(result["result"]["metadata"], {"purpose": "test"})
            self.assertEqual(state.get_job("job-execution-0001"), result)

    def test_unrepresentable_result_does_not_kill_job_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = agent.AgentState(Path(directory), start_worker=False)
            state.submit_job(
                {
                    "schema_version": 1,
                    "job_id": "job-bad-repr-0001",
                    "code": (
                        "class BadRepr:\n"
                        "    def __repr__(self):\n"
                        "        raise RuntimeError('no repr')\n"
                        "GRABOWSKI_RESULT = BadRepr()\n"
                    ),
                    "timeout_seconds": 5,
                    "metadata": {},
                }
            )
            result = state.run_job_now("job-bad-repr-0001")
            self.assertEqual(result["state"], "succeeded")
            self.assertEqual(
                result["result"],
                "<unrepresentable BadRepr: RuntimeError>",
            )

    def test_duplicate_job_id_is_create_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = agent.AgentState(Path(directory), start_worker=False)
            document = {
                "schema_version": 1,
                "job_id": "job-duplicate-0001",
                "code": "GRABOWSKI_RESULT = 1",
                "timeout_seconds": 5,
                "metadata": {},
            }
            state.submit_job(document)
            with self.assertRaisesRegex(FileExistsError, "job_id_already_exists"):
                state.submit_job(document)

    def test_pure_python_loop_times_out(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = agent.AgentState(Path(directory), start_worker=False)
            state.submit_job(
                {
                    "schema_version": 1,
                    "job_id": "job-timeout-0001",
                    "code": "while True:\n    pass\n",
                    "timeout_seconds": 1,
                    "metadata": {},
                }
            )
            started = time.monotonic()
            result = state.run_job_now("job-timeout-0001")
            elapsed = time.monotonic() - started
            self.assertEqual(result["state"], "timed_out")
            self.assertLess(elapsed, 3.0)

    def test_restart_marks_nonterminal_job_abandoned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = agent.AgentState(root, start_worker=False)
            first.submit_job(
                {
                    "schema_version": 1,
                    "job_id": "job-recovery-0001",
                    "code": "GRABOWSKI_RESULT = 1",
                    "timeout_seconds": 5,
                    "metadata": {},
                }
            )
            second = agent.AgentState(root, start_worker=False)
            result = second.get_job("job-recovery-0001")
            self.assertEqual(result["state"], "abandoned_after_restart")
            audit_lines = (root / "audit.jsonl").read_text(encoding="utf-8").splitlines()
            events = [json.loads(line)["event"] for line in audit_lines]
            self.assertIn("job_recovered", events)


class HTTPIntegrationTests(unittest.TestCase):
    def test_authenticated_job_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            secret = b"k" * 32
            state = agent.AgentState(Path(directory))
            server = agent.AgentHTTPServer(
                ("127.0.0.1", 0),
                agent.AgentHandler,
                authenticator=agent.RequestAuthenticator(secret),
                state=state,
                secret_source="test",
                started_at=agent.utc_now(),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_address[1]}"
                client = client_module.AgentClient(base_url, secret, 3.0)
                health = client.health()
                self.assertTrue(health["arbitrary_python"])
                submitted = client.submit(
                    "GRABOWSKI_RESULT = {'value': 7}",
                    timeout_seconds=5,
                    metadata={"transport": "http"},
                    job_id="job-http-0001",
                )
                self.assertIn(submitted["state"], {"queued", "running", "succeeded"})
                deadline = time.monotonic() + 5
                while True:
                    result = client.status("job-http-0001")
                    if result["state"] in agent.TERMINAL_STATES:
                        break
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                self.assertEqual(result["state"], "succeeded")
                self.assertEqual(result["result"], {"value": 7})
                listed = client.list_jobs(10)
                self.assertEqual(listed["jobs"][0]["job_id"], "job-http-0001")
            finally:
                server.shutdown()
                server.server_close()
                state.stop()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()

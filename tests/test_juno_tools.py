from __future__ import annotations

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import grabowski_juno as bridge


AGENT_PATH = ROOT / "tools/juno/juno_ipad_agent.py"


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


agent = load_module("test_juno_tools_agent_module", AGENT_PATH)


class JunoToolIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = agent.AgentState(self.root / "agent-state")
        self.server = agent.AgentHTTPServer(
            ("127.0.0.1", 0),
            agent.AgentHandler,
            authenticator=None,
            state=self.state,
            secret_source="unpaired",
            key_path=self.root / "agent-state" / "juno_ipad_agent.key",
            pairing_peer="127.0.0.1",
            started_at=agent.utc_now(),
            pairing_consent_code="123456",
            pairing_consent_expires_at_unix=int(time.time()) + 600,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.secret_path = self.root / "client-secrets" / "juno-ipad-agent.key"
        self.receipt_root = self.root / "receipts"
        self.patches = [
            patch.object(
                bridge,
                "AGENT_URL",
                f"http://127.0.0.1:{self.server.server_address[1]}",
            ),
            patch.object(bridge, "EXPECTED_AGENT_HOST", "127.0.0.1"),
            patch.object(
                bridge,
                "EXPECTED_AGENT_PORT",
                self.server.server_address[1],
            ),
            patch.object(bridge, "EXPECTED_PAIRING_PEER", "127.0.0.1"),
            patch.object(bridge, "SECRET_PATH", self.secret_path),
            patch.object(bridge, "RECEIPT_ROOT", self.receipt_root),
            patch.object(
                bridge.operator,
                "_require_operator_mutation",
                return_value=None,
                create=True,
            ),
            patch.object(
                bridge.operator,
                "_require_operator_capability",
                return_value=None,
                create=True,
            ),
        ]
        for active_patch in self.patches:
            active_patch.start()
        self.started_at = bridge.grabowski_juno_status()["health"]["started_at"]

    def tearDown(self) -> None:
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.server.shutdown()
        self.server.server_close()
        self.state.stop()
        self.thread.join(timeout=3)
        self.temporary.cleanup()

    @staticmethod
    def escalation() -> dict[str, object]:
        return {
            "target": {"device": bridge.AGENT_ID},
            "reason": "test exact Juno device authority",
            "expires_at_unix": int(time.time()) + 300,
            "recovery": {"path": "stop the local Juno agent"},
        }

    def pair(self) -> dict[str, object]:
        return bridge.grabowski_juno_pair(
            consent_code="123456",
            expected_started_at=self.started_at,
            session_escalation=self.escalation(),
        )

    def test_pair_requires_visible_code_and_never_returns_secret(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "HTTP 403"):
            bridge.grabowski_juno_pair(
                consent_code="654321",
                expected_started_at=self.started_at,
                session_escalation=self.escalation(),
            )
        self.assertFalse(self.secret_path.exists())
        pending = self.secret_path.with_name(
            f".{self.secret_path.name}.pairing-pending"
        )
        self.assertTrue(pending.is_file())

        result = self.pair()
        self.assertEqual(result["status"], "paired")
        self.assertTrue(self.secret_path.is_file())
        self.assertEqual(self.secret_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.secret_path.read_bytes()), 32)
        self.assertFalse(pending.exists())

        rendered = json.dumps(result, ensure_ascii=False, sort_keys=True)
        self.assertNotIn("123456", rendered)
        self.assertNotIn("secret_b64", rendered)
        receipt_path = Path(result["receipt"]["path"])
        self.assertTrue(receipt_path.is_file())
        receipt_text = receipt_path.read_text(encoding="utf-8")
        self.assertNotIn("123456", receipt_text)
        self.assertNotIn("secret_b64", receipt_text)

    def test_hash_bound_job_round_trip_and_status(self) -> None:
        self.pair()
        code = (
            "print('typed Juno test')\n"
            "GRABOWSKI_RESULT = {'value': 9, 'device': 'ipad'}\n"
        )
        code_sha256 = hashlib.sha256(code.encode("utf-8")).hexdigest()
        result = bridge.grabowski_juno_run(
            code=code,
            code_sha256=code_sha256,
            purpose="verify typed Juno execution path",
            expected_started_at=self.started_at,
            session_escalation=self.escalation(),
            timeout_seconds=5,
        )
        self.assertEqual(result["code_sha256"], code_sha256)
        self.assertEqual(result["status"]["state"], "succeeded")
        self.assertEqual(result["status"]["result"], {"device": "ipad", "value": 9})
        self.assertEqual(result["status"]["stdout"], "typed Juno test\n")
        self.assertTrue(Path(result["receipt"]["path"]).is_file())

        observed = bridge.grabowski_juno_status(result["job_id"])
        self.assertEqual(observed["job"]["state"], "succeeded")
        self.assertEqual(observed["job"]["code_sha256"], code_sha256)

    def test_job_rejects_code_hash_drift_before_submission(self) -> None:
        self.pair()
        with self.assertRaisesRegex(ValueError, "does not match"):
            bridge.grabowski_juno_run(
                code="GRABOWSKI_RESULT = 1\n",
                code_sha256="0" * 64,
                purpose="reject changed code",
                expected_started_at=self.started_at,
                session_escalation=self.escalation(),
                timeout_seconds=5,
            )
        jobs = bridge._request(
            "GET",
            "/v1/jobs?limit=20",
            secret=bridge._read_private_secret(),
        )
        self.assertEqual(jobs["jobs"], [])

    def test_exact_agent_instance_and_peer_are_required(self) -> None:
        health = bridge.grabowski_juno_status()["health"]
        with self.assertRaisesRegex(RuntimeError, "instance changed"):
            bridge._validate_expected_agent(health, "other-start")
        altered = dict(health)
        altered["pairing_peer"] = "100.64.0.99"
        with self.assertRaisesRegex(RuntimeError, "not bound"):
            bridge._validate_expected_agent(altered, self.started_at)

    def test_endpoint_and_escalation_require_exact_targets(self) -> None:
        bridge._validate_escalation(self.escalation())
        altered = self.escalation()
        altered["target"] = {"device": f"prefix-{bridge.AGENT_ID}"}
        with self.assertRaisesRegex(PermissionError, "not bound"):
            bridge._validate_escalation(altered)
        with patch.object(bridge, "AGENT_URL", "http://127.0.0.2:8765"):
            with self.assertRaisesRegex(RuntimeError, "exact private endpoint"):
                bridge._validated_agent_base_url()

    def test_http_redirects_are_not_followed(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                self.send_response(307)
                self.send_header("Location", "/health")
                self.send_header("Content-Length", "0")
                self.end_headers()

        redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(
            target=redirect_server.serve_forever,
            daemon=True,
        )
        redirect_thread.start()
        try:
            port = redirect_server.server_address[1]
            with (
                patch.object(bridge, "AGENT_URL", f"http://127.0.0.1:{port}"),
                patch.object(bridge, "EXPECTED_AGENT_HOST", "127.0.0.1"),
                patch.object(bridge, "EXPECTED_AGENT_PORT", port),
            ):
                with self.assertRaisesRegex(RuntimeError, "HTTP 307"):
                    bridge._request("GET", "/health")
        finally:
            redirect_server.shutdown()
            redirect_server.server_close()
            redirect_thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass
    def tool(self, *args, **kwargs):
        return lambda function: function

class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs

if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_workers as workers


def result(returncode: int = 0, stdout: str = "") -> dict[str, object]:
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }

class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = self.root / "workers"
        self.db = self.state / "workers.sqlite3"
        self.resource_db = self.root / "resources.sqlite3"
        self.patches = [
            patch.object(workers, "WORKER_STATE", self.state),
            patch.object(workers, "WORKER_DB", self.db),
            patch.object(workers.resources, "RESOURCE_DB", self.resource_db),
        ]
        for item in self.patches:
            item.start()
        self.binary = self.root / "browser"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def _run_browser_form_node(
        self,
        scenario: str,
        *,
        cleanup_only: bool = True,
        action_mode: str = "readiness",
        allowed_addresses: list[str] | None = None,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is required for the browser helper runtime test")
        helper_path = self.root / "stored-form-helper.mjs"
        preload_path = self.root / "fake-cdp.mjs"
        request_path = self.root / "request.json"
        helper_path.write_text(workers.BROWSER_FORM_NODE_SOURCE, encoding="utf-8")
        preload_path.write_text(
            r"""
const scenario = process.env.GRABOWSKI_TEST_SCENARIO;
const expectedOrigin = 'http://device.home.arpa';
const allowedAddress = '192.168.1.10';
const initialLoader = 'loader-before-reload';
const reloadLoader = 'loader-after-reload';
let frameTreeCalls = 0;

function message(target, payload) {
  if (target.onmessage) target.onmessage({data: JSON.stringify(payload)});
}

class FakeWebSocket {
  static OPEN = 1;

  constructor() {
    this.readyState = 0;
    queueMicrotask(() => {
      this.readyState = FakeWebSocket.OPEN;
      if (this.onopen) this.onopen();
    });
  }

  send(raw) {
    const request = JSON.parse(raw);
    const reply = (result = {}) => {
      message(this, {id: request.id, result});
    };
    const fail = () => {
      message(this, {id: request.id, error: {message: 'protocol'}});
    };
    const emit = (method, params = {}) => {
      message(this, {method, params});
    };
    switch (request.method) {
      case 'Runtime.enable':
      case 'Page.enable':
      case 'Page.setLifecycleEventsEnabled':
      case 'Network.enable':
      case 'Network.setCacheDisabled':
      case 'Input.dispatchMouseEvent':
      case 'Input.dispatchKeyEvent':
        reply();
        return;
      case 'Page.getFrameTree': {
        frameTreeCalls += 1;
        const finalOrigin = scenario === 'wrong-final-origin'
          ? 'http://other.home.arpa' : expectedOrigin;
        reply({
          frameTree: {
            frame: {
              id: 'main',
              loaderId: frameTreeCalls === 1 ? initialLoader : reloadLoader,
              url: (frameTreeCalls === 1 ? expectedOrigin : finalOrigin) + '/',
            },
          },
        });
        if (frameTreeCalls === 1 && scenario === 'stale-events') {
          emit('Network.responseReceived', {
            requestId: 'stale-document',
            loaderId: initialLoader,
            type: 'Document',
            frameId: 'main',
            response: {
              url: expectedOrigin + '/',
              remoteIPAddress: allowedAddress,
            },
          });
          emit('Page.lifecycleEvent', {
            name: 'load', frameId: 'main', loaderId: initialLoader,
          });
        }
        return;
      }
      case 'Page.reload': {
        if (request.params.loaderId !== initialLoader) {
          fail();
          return;
        }
        if (scenario === 'old-loader-events-during-reload') {
          emit('Network.responseReceived', {
            requestId: 'old-loader-document',
            loaderId: initialLoader,
            type: 'Document',
            frameId: 'main',
            response: {url: expectedOrigin + '/', remoteIPAddress: allowedAddress},
          });
          emit('Page.lifecycleEvent', {
            name: 'load', frameId: 'main', loaderId: initialLoader,
          });
        }
        const remoteIPAddress = scenario === 'disallowed-address'
          ? '203.0.113.7'
          : (scenario === 'invalid-address'
            ? 'not-an-ip'
            : (scenario === 'ipv6-zone-address' ? '[fd00:0:0::1%eth0]' : allowedAddress));
        const responseLoader = scenario === 'loader-mismatch'
          ? 'different-loader' : reloadLoader;
        emit('Network.responseReceived', {
          requestId: 'reload-document',
          loaderId: responseLoader,
          type: 'Document',
          frameId: 'main',
          response: {url: expectedOrigin + '/', remoteIPAddress},
        });
        if (scenario === 'response-then-close') {
          this.readyState = 3;
          if (this.onclose) this.onclose();
          return;
        }
        emit('Page.lifecycleEvent', {
          name: 'load', frameId: 'main', loaderId: reloadLoader,
        });
        reply();
        return;
      }
      case 'Runtime.evaluate': {
        const expression = String(request.params.expression || '');
        if (expression.includes('identity_type: identityType')) {
          if (scenario === 'verified-then-element-failure') {
            reply({result: {value: {valid: false}}});
          } else {
            reply({result: {value: {
              valid: true,
              origin: expectedOrigin,
              identity_type: 'text',
              protected_type: 'password',
              submit_type: 'submit',
              identity_visible: true,
              protected_visible: true,
              submit_visible: true,
              identity_disabled: false,
              protected_disabled: false,
              submit_disabled: false,
            }}});
          }
          return;
        }
        if (expression.includes('document.elementFromPoint')) {
          reply({result: {value: {x: 10, y: 10}}});
          return;
        }
        if (expression.includes('identity_filled')) {
          reply({result: {value: {identity_filled: true, protected_filled: true}}});
          return;
        }
        reply({result: {value: true}});
        return;
      }
      default:
        reply();
    }
  }

  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    queueMicrotask(() => {
      if (this.onclose) this.onclose();
    });
  }
}

globalThis.WebSocket = FakeWebSocket;
globalThis.fetch = async () => ({
  ok: true,
  json: async () => [{
    type: 'page',
    url: expectedOrigin + '/',
    webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/page/1',
  }],
});
""",
            encoding="utf-8",
        )
        request_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "port": 9222,
                    "expected_origin": "http://device.home.arpa",
                    "allowed_addresses": allowed_addresses or ["192.168.1.10"],
                    "cleanup_only": cleanup_only,
                    "action_mode": action_mode,
                    "selectors": {
                        "identity": "#identity",
                        "protected": "#protected",
                        "submit": "button",
                    },
                    "identity_choice": None,
                    "timeout_ms": 250,
                }
            ),
            encoding="utf-8",
        )
        execution = subprocess.run(
            [node, "--import", str(preload_path), str(helper_path), str(request_path)],
            cwd=self.root,
            env={**os.environ, "GRABOWSKI_TEST_SCENARIO": scenario},
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        lines = [line for line in execution.stdout.splitlines() if line.strip()]
        self.assertTrue(lines, execution.stderr)
        return execution, json.loads(lines[-1])

    def test_browser_launch_is_loopback_only_and_leased(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ) as run:
            started = workers.browser_start(
                str(self.binary), port=9222, args=["--headless=new"], runtime_seconds=60
            )
        worker = started["worker"]
        self.assertEqual(worker["kind"], "browser")
        self.assertEqual(worker["state"], "running")
        self.assertIn("--remote-debugging-address=127.0.0.1", worker["argv"])
        self.assertIn("--remote-debugging-port=9222", worker["argv"])
        launch = run.call_args.args[0]
        descriptions = [item for item in launch if item.startswith("--description=")]
        self.assertEqual(1, len(descriptions))
        self.assertIn("Grabowski browser-worker grabowski-browser-worker-", descriptions[0])
        self.assertIn(" argv=", descriptions[0])
        self.assertNotIn("\n", descriptions[0])
        self.assertIn("--slice=grabowski-workers.slice", launch)
        self.assertEqual(launch.count("--property=LimitCORE=0"), 1)
        self.assertIn("--property=NoNewPrivileges=yes", launch)
        self.assertEqual(
            workers.resources.inspect_resource("port:9222")["owner_id"],
            f"worker:{worker['worker_id']}",
        )

    def test_persistent_profile_ignores_missing_alternative_roots(self) -> None:
        existing_root = self.root / "brave"
        existing_root.mkdir()
        missing_root = self.root / "chromium"
        profile = existing_root / "schauwerk"
        configured_roots = [str(existing_root), str(missing_root)]

        with patch.object(
            workers.base, "_load_policy", return_value={}
        ), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ):
            resolved, ephemeral = workers._browser_profile("0" * 20, str(profile))

        self.assertEqual(resolved, profile)
        self.assertTrue(resolved.is_dir())
        self.assertFalse(ephemeral)

    def test_browser_args_cannot_override_binding_or_profile(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()):
            for argument in (
                "--remote-debugging-address=0.0.0.0",
                "--remote-debugging-port=9999",
                "--user-data-dir=/tmp/x",
            ):
                with self.assertRaises(ValueError):
                    workers.browser_start(str(self.binary), port=9222, args=[argument])

    def test_terminal_status_releases_leases_and_ephemeral_profile(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9223, runtime_seconds=60)
        worker = started["worker"]
        profile = Path(worker["profile_path"])
        self.assertTrue(profile.exists())
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9223"))
        self.assertFalse(profile.exists())

    def test_collected_successful_unit_is_completed(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9225, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9225"))

    def test_collected_failed_unit_is_failed(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9226, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=exit-code\nExecMainStatus=1\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")
        self.assertIsNone(workers.resources.inspect_resource("port:9226"))

    def test_collected_unit_without_result_is_interrupted(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9227, runtime_seconds=60)
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=\nExecMainStatus=\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "interrupted")
        self.assertIsNone(workers.resources.inspect_resource("port:9227"))

    def _running_browser(self, port: int = 9333) -> dict[str, object]:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            return workers.browser_start(str(self.binary), port=port, runtime_seconds=60)["worker"]

    def _confirmation(
        self,
        worker_id: str,
        *,
        origin: str = "http://device.home.arpa",
        identity: str = "#identity",
        protected: str = "#protected",
        submit: str = "button",
        choice: str | None = None,
        action_mode: str = "submit",
    ) -> str:
        scope, _, _ = workers._browser_form_action_scope(
            worker_id,
            origin,
            {"identity": identity, "protected": protected, "submit": submit},
            choice,
            action_mode,
        )
        return workers._browser_form_confirmation(worker_id, origin, scope)

    def test_stored_form_action_is_target_bound_and_redacted(self) -> None:
        worker = self._running_browser()
        payload = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "fill_confirmed": True,
            "submitted": True,
            "action_effect_observed": True,
            "navigation_observed": False,
            "form_disappeared": True,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": "a" * 64,
            "remote_address_sha256": "d" * 64,
            "cleaned": False,
        }
        audit_path = self.root / "audit.jsonl"
        with patch.object(workers, "_canonical_local_origin", return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"])), patch.object(
            workers, "_run_node_form_action", return_value=payload
        ) as action, patch.object(workers.base, "_append_audit") as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(workers.base, "AUDIT_LOG", audit_path), patch.object(
            workers, "_observe", return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1}
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button[type=submit]",
                identity_choice="operator",
                confirmation=self._confirmation(
                    worker["worker_id"],
                    submit="button[type=submit]",
                    choice="operator",
                ),
            )
        self.assertTrue(response["ok"])
        self.assertTrue(response["submitted"])
        self.assertNotIn("#identity", json.dumps(response))
        self.assertNotIn("#protected", json.dumps(response))
        request = action.call_args.args[1]
        self.assertEqual(request["expected_origin"], "http://device.home.arpa")
        record = append.call_args.args[0]
        self.assertNotIn("identity_selector", record)
        self.assertNotIn("protected_selector", record)
        self.assertEqual(record["selector_sha256"]["identity"], workers._sha256_text("#identity"))
        self.assertIsNone(workers.resources.inspect_resource(f"component:browser-action:{worker['worker_id']}"))

    def test_stored_form_readiness_is_fill_only_and_cleans_fields(self) -> None:
        worker = self._running_browser(port=9342)
        payload = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ready",
            "fill_confirmed": True,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_run_node_form_action", return_value=payload) as action, patch.object(
            workers.base, "_append_audit"
        ) as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(
            workers,
            "_observe",
            return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1},
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                action_mode="readiness",
                confirmation=self._confirmation(worker["worker_id"], action_mode="readiness"),
            )
        self.assertTrue(response["ok"])
        self.assertEqual(response["result_code"], "ready")
        self.assertIs(response["submitted"], False)
        self.assertIs(response["cleaned"], True)
        self.assertEqual(response["action_mode"], "readiness")
        self.assertEqual(action.call_args.args[1]["action_mode"], "readiness")
        self.assertEqual(append.call_args.args[0]["action_mode"], "readiness")
        self.assertEqual(
            response["does_not_establish"],
            [
                "authentication_success",
                "future_submit_success",
                "browser_profile_contains_a_reusable_stored_entry",
            ],
        )

    def test_stored_form_action_rejects_invalid_mode_before_transport(self) -> None:
        worker = self._running_browser(port=9344)
        with patch.object(workers, "_canonical_local_origin") as origin, patch.object(
            workers, "_run_node_form_action"
        ) as action:
            with self.assertRaisesRegex(ValueError, "action_mode"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    action_mode="inspect",
                    confirmation="unused",
                )
        origin.assert_not_called()
        action.assert_not_called()

    def test_stored_form_readiness_rejects_drifted_success_receipts(self) -> None:
        worker = self._running_browser(port=9345)
        base_payload = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ready",
            "fill_confirmed": True,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        record = workers._row(worker["worker_id"])
        request = {
            "schema_version": 1,
            "port": 9345,
            "expected_origin": "http://device.home.arpa",
            "allowed_addresses": ["192.168.1.1"],
            "cleanup_only": False,
            "action_mode": "readiness",
            "selectors": {"identity": "#i", "protected": "#p", "submit": "button"},
            "identity_choice": None,
            "timeout_ms": 5000,
        }
        for key, value in (
            ("form_disappeared", True),
            ("post_origin", "http://other.home.arpa"),
            ("post_path_sha256", "a" * 64),
        ):
            with self.subTest(key=key):
                payload = {**base_payload, key: value}
                execution = result(stdout=json.dumps(payload) + "\n")
                node = self.root / f"node-{key}"
                node.write_text("#!/bin/sh\nexit 0\n")
                node.chmod(0o755)
                with patch.object(workers.shutil, "which", return_value=str(node)), patch.object(
                    workers.operator, "_run", return_value=execution
                ):
                    with self.assertRaisesRegex(RuntimeError, "readiness receipt"):
                        workers._run_node_form_action(
                            record,
                            request,
                            timeout_seconds=5,
                        )

    def test_stored_form_readiness_confirmation_cannot_authorize_submit(self) -> None:
        worker = self._running_browser(port=9343)
        readiness_confirmation = self._confirmation(
            worker["worker_id"], action_mode="readiness"
        )
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_run_node_form_action") as action:
            with self.assertRaisesRegex(PermissionError, "confirmation mismatch"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    action_mode="submit",
                    confirmation=readiness_confirmation,
                )
        action.assert_not_called()

    def test_stored_form_readiness_helper_clears_before_submit_branch(self) -> None:
        source = workers.BROWSER_FORM_NODE_SOURCE
        readiness = source.index("if (request.action_mode === 'readiness')")
        clear = source.index("cleaned = await clearFields();", readiness)
        ready_receipt = source.index("result_code: 'ready'", readiness)
        submit = source.index("stage = 'submit-target';", readiness)
        self.assertLess(readiness, clear)
        self.assertLess(clear, ready_receipt)
        self.assertLess(ready_receipt, submit)

    def test_stored_form_action_requires_exact_confirmation(self) -> None:
        worker = self._running_browser(port=9334)
        with patch.object(workers, "_canonical_local_origin", return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"])), patch.object(
            workers, "_run_node_form_action"
        ) as action:
            with self.assertRaisesRegex(PermissionError, "confirmation mismatch"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation="wrong",
                )
        action.assert_not_called()

    def test_stored_form_action_rejects_public_resolution(self) -> None:
        public_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        with patch.object(workers.socket, "getaddrinfo", return_value=public_answer):
            with self.assertRaisesRegex(PermissionError, "outside local"):
                workers._canonical_local_origin("http://example.invalid")

    def test_stored_form_action_canonicalizes_resolved_ipv6_addresses(self) -> None:
        local_answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00:0:0:0:0:0:0:1", 80, 0, 3)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 80, 0, 0)),
        ]
        with patch.object(workers.socket, "getaddrinfo", return_value=local_answers):
            origin, address_sha256, addresses = workers._canonical_local_origin(
                "http://device.invalid"
            )
        self.assertEqual(origin, "http://device.invalid")
        self.assertEqual(addresses, ["fd00::1"])
        self.assertEqual(address_sha256, hashlib.sha256(b"fd00::1").hexdigest())

    def test_stored_form_action_rejects_invalid_resolver_address(self) -> None:
        invalid_answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 80))
        ]
        with patch.object(workers.socket, "getaddrinfo", return_value=invalid_answers):
            with self.assertRaisesRegex(RuntimeError, "invalid address"):
                workers._canonical_local_origin("http://device.invalid")

    def test_stored_form_action_rejects_multiline_selector(self) -> None:
        with self.assertRaisesRegex(ValueError, "bounded single-line"):
            workers._validate_form_selector("#field\nscript", "identity_selector")

    def test_stored_form_action_fails_closed_when_browser_fill_is_absent(self) -> None:
        worker = self._running_browser(port=9335)
        payload = {
            "schema_version": 1,
            "ok": False,
            "result_code": "browser-fill",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        with patch.object(workers, "_canonical_local_origin", return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"])), patch.object(
            workers, "_run_node_form_action", return_value=payload
        ), patch.object(workers.base, "_append_audit") as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(workers, "_observe", return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1}):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                confirmation=self._confirmation(worker["worker_id"]),
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["result_code"], "browser-fill")
        self.assertTrue(response["cleaned"])
        self.assertTrue(append.call_args.args[0]["cleaned"])

    def test_node_action_removes_private_request_files(self) -> None:
        worker = self._running_browser(port=9336)
        record = workers._row(worker["worker_id"])
        output = json.dumps({
            "schema_version": 1,
            "ok": False,
            "result_code": "transport",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": None,
            "cleaned": False,
        }) + "\n"
        node_target = self.root / "heim-node-tool"
        node_target.write_text("#!/bin/sh\nexit 0\n")
        node_target.chmod(0o755)
        node = self.root / "node"
        node.symlink_to(node_target)
        with patch.object(workers.shutil, "which", return_value=str(node)), patch.object(
            workers.operator, "_run", return_value=result(returncode=2, stdout=output)
        ) as run:
            parsed = workers._run_node_form_action(
                record,
                {
                    "schema_version": 1,
                    "port": 9336,
                    "expected_origin": "http://device.home.arpa",
                    "allowed_addresses": ["192.168.1.1"],
                    "cleanup_only": False,
                    "selectors": {"identity": "#i", "protected": "#p", "submit": "button"},
                    "identity_choice": None,
                    "timeout_ms": 5000,
                },
                timeout_seconds=5,
            )
        self.assertEqual(parsed["result_code"], "transport")
        self.assertEqual(run.call_args.args[0][0], str(node))
        self.assertNotEqual(run.call_args.args[0][0], str(node_target))
        instance = Path(record["config_path"]).parent
        self.assertEqual(list(instance.glob(".stored-form-*")), [])

    def test_stored_form_action_rejects_origin_path_query_and_fragment(self) -> None:
        local_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 80))]
        with patch.object(workers.socket, "getaddrinfo", return_value=local_answer):
            for value in (
                "http://device.home.arpa/login",
                "http://device.home.arpa?next=login",
                "http://device.home.arpa/#login",
            ):
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "canonical"):
                    workers._canonical_local_origin(value)

    def test_stored_form_action_rejects_terminal_worker_before_transport(self) -> None:
        worker = self._running_browser(port=9337)
        completed = {
            "state": "completed",
            "properties": {},
            "probe": result(),
            "observed_at_unix": 1,
        }
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_observe", return_value=completed), patch.object(
            workers, "_run_node_form_action"
        ) as action:
            with self.assertRaisesRegex(RuntimeError, "not running"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation=self._confirmation(worker["worker_id"]),
                )
        action.assert_not_called()

    def test_stored_form_action_audits_protocol_failure_after_cleanup_retry(self) -> None:
        worker = self._running_browser(port=9338)
        cleanup = {
            "schema_version": 1,
            "ok": True,
            "result_code": "cleanup",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": "http://device.home.arpa",
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        audit_path = self.root / "audit.jsonl"
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(
            workers,
            "_run_node_form_action",
            side_effect=[RuntimeError("untrusted internal detail"), cleanup],
        ) as action, patch.object(workers.base, "_append_audit") as append, patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(workers.base, "AUDIT_LOG", audit_path), patch.object(
            workers,
            "_observe",
            return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1},
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                confirmation=self._confirmation(worker["worker_id"]),
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["result_code"], "protocol")
        self.assertNotIn("untrusted internal detail", json.dumps(response))
        self.assertEqual(action.call_count, 2)
        self.assertEqual(append.call_count, 2)
        self.assertIs(action.call_args_list[1].args[1]["cleanup_only"], True)
        record = append.call_args.args[0]
        self.assertEqual(record["result_code"], "protocol")
        self.assertIs(record["outcome_known"], False)
        self.assertIsNone(record["ok"])
        self.assertIsNone(record["submitted"])
        self.assertTrue(record["cleaned"])
        self.assertNotIn("untrusted internal detail", json.dumps(record))
        self.assertIsNone(
            workers.resources.inspect_resource(
                f"component:browser-action:{worker['worker_id']}"
            )
        )

    def test_stored_form_action_preserves_fixed_element_contract_failure(self) -> None:
        worker = self._running_browser(port=9339)
        payload = {
            "schema_version": 1,
            "ok": False,
            "result_code": "element-contract",
            "fill_confirmed": False,
            "submitted": False,
            "action_effect_observed": False,
            "navigation_observed": False,
            "form_disappeared": False,
            "post_origin": None,
            "post_path_sha256": None,
            "remote_address_sha256": "d" * 64,
            "cleaned": True,
        }
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_run_node_form_action", return_value=payload), patch.object(
            workers.base, "_append_audit"
        ), patch.object(
            workers.base, "_verify_audit_log", return_value={"last_record_sha256": "c" * 64}
        ), patch.object(
            workers,
            "_observe",
            return_value={"state": "running", "properties": {}, "probe": result(), "observed_at_unix": 1},
        ):
            response = workers.browser_stored_form_action(
                worker["worker_id"],
                expected_origin="http://device.home.arpa",
                identity_selector="#identity",
                protected_selector="#protected",
                submit_selector="button",
                confirmation=self._confirmation(worker["worker_id"]),
            )
        self.assertFalse(response["ok"])
        self.assertEqual(response["result_code"], "element-contract")
        self.assertTrue(response["cleaned"])

    def test_stored_form_confirmation_changes_with_every_selector(self) -> None:
        worker = self._running_browser(port=9340)
        original = self._confirmation(worker["worker_id"])
        for key, kwargs in (
            ("identity", {"identity": "#other-identity"}),
            ("protected", {"protected": "#other-protected"}),
            ("submit", {"submit": "button.primary"}),
            ("choice", {"choice": "other-user"}),
            ("action_mode", {"action_mode": "readiness"}),
        ):
            with self.subTest(key=key):
                self.assertNotEqual(original, self._confirmation(worker["worker_id"], **kwargs))

    def test_stored_form_action_requires_worker_owned_port_lease(self) -> None:
        worker = self._running_browser(port=9341)
        workers.resources.release_resources(
            f"worker:{worker['worker_id']}",
            ["port:9341"],
        )
        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(workers, "_observe", return_value={
            "state": "running",
            "properties": {},
            "probe": result(),
            "observed_at_unix": 1,
        }), patch.object(workers, "_run_node_form_action") as action:
            with self.assertRaisesRegex(RuntimeError, "no longer owns"):
                workers.browser_stored_form_action(
                    worker["worker_id"],
                    expected_origin="http://device.home.arpa",
                    identity_selector="#identity",
                    protected_selector="#protected",
                    submit_selector="button",
                    confirmation=self._confirmation(worker["worker_id"]),
                )
        action.assert_not_called()

    def test_stored_form_helper_handles_prearmed_reload_events_at_runtime(self) -> None:
        execution, receipt = self._run_browser_form_node("reload-events-before-reply")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(receipt["result_code"], "cleanup")
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_ignores_stale_pre_reload_events(self) -> None:
        execution, receipt = self._run_browser_form_node("stale-events")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_ignores_old_loader_events_during_reload(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "old-loader-events-during-reload"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_rejects_loader_mismatch(self) -> None:
        execution, receipt = self._run_browser_form_node("loader-mismatch")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_rejects_final_frame_origin_drift(self) -> None:
        execution, receipt = self._run_browser_form_node("wrong-final-origin")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_does_not_claim_incomplete_transport_evidence(self) -> None:
        execution, receipt = self._run_browser_form_node("response-then-close")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertIs(receipt["ok"], False)
        self.assertEqual(receipt["result_code"], "transport")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_preserves_digest_after_verified_later_failure(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "verified-then-element-failure", cleanup_only=False
        )
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "element-contract")
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"192.168.1.10").hexdigest(),
        )

    def test_stored_form_helper_does_not_disclose_rejected_remote_address(self) -> None:
        execution, receipt = self._run_browser_form_node("disallowed-address")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertIs(receipt["ok"], False)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_rejects_invalid_remote_address(self) -> None:
        execution, receipt = self._run_browser_form_node("invalid-address")
        self.assertEqual(execution.returncode, 2, execution.stderr)
        self.assertEqual(receipt["result_code"], "target-origin")
        self.assertIsNone(receipt["remote_address_sha256"])

    def test_stored_form_helper_normalizes_ipv6_zone_address(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "ipv6-zone-address", allowed_addresses=["fd00::1"]
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(
            receipt["remote_address_sha256"],
            hashlib.sha256(b"fd00::1").hexdigest(),
        )

    def test_stored_form_helper_executes_non_cleanup_readiness_path(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "readiness-success", cleanup_only=False, action_mode="readiness"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertIs(receipt["ok"], True)
        self.assertEqual(receipt["result_code"], "ready")
        self.assertIs(receipt["fill_confirmed"], True)
        self.assertIs(receipt["cleaned"], True)

    def test_stored_form_helper_uses_topmost_pointer_and_guarded_enter(self) -> None:
        source = workers.BROWSER_FORM_NODE_SOURCE
        self.assertIn("document.elementFromPoint", source)
        self.assertIn("Input.dispatchMouseEvent", source)
        self.assertIn("guardedEnter", source)
        browser_fill = source.split("stage = 'browser-fill';", 1)[1].split(
            "stage = 'submit-target';", 1
        )[0]
        self.assertNotIn(".focus()", browser_fill)
        self.assertIn("await key('Tab', 'Tab', 9)", browser_fill)
        self.assertIn("await guardedEnter()", browser_fill)

    def test_gui_fails_clearly_without_xvfb(self) -> None:
        with patch.object(workers.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Xvfb is not installed"):
                workers.gui_start(str(self.binary), display_number=20)

    def test_gui_config_has_no_tcp_listener(self) -> None:
        xvfb = self.root / "Xvfb"
        xvfb.write_text("#!/bin/sh\nexit 0\n")
        xvfb.chmod(0o755)
        with patch.object(workers.shutil, "which", return_value=str(xvfb)), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.gui_start(
                str(self.binary), display_number=21, args=["--example"], runtime_seconds=60
            )
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        config = json.loads(Path(record["config_path"]).read_text())
        self.assertEqual(config["environment"]["DISPLAY"], ":21")
        self.assertIn("-nolisten", config["xvfb_argv"])
        self.assertIn("tcp", config["xvfb_argv"])
        self.assertNotIn("vnc", " ".join(config["xvfb_argv"]).lower())
        self.assertEqual(
            workers.resources.inspect_resource("display:21")["owner_id"],
            f"worker:{worker['worker_id']}",
        )

    def test_launch_failure_releases_worker_leases(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result(returncode=1)
        ):
            started = workers.browser_start(str(self.binary), port=9224, runtime_seconds=60)
        self.assertEqual(started["worker"]["state"], "failed")
        self.assertIsNone(workers.resources.inspect_resource("port:9224"))

if __name__ == "__main__":
    unittest.main()

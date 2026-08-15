from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import socket
import sqlite3
import stat
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
        self.binary = self.root / "google-chrome"
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
let formContractCalls = 0;
let clearFieldsCalls = 0;

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
          setInterval(() => {}, 1000);
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
          formContractCalls += 1;
          if (scenario === 'verified-then-element-failure') {
            reply({result: {value: {
              valid: false, origin: expectedOrigin, selector_error: true,
            }}});
          } else if (scenario === 'delayed-form-hydration' && formContractCalls < 3) {
            reply({result: {value: {
              valid: false, origin: expectedOrigin, selector_error: false,
            }}});
          } else {
            reply({result: {value: {
              valid: true,
              origin: expectedOrigin,
              selector_error: false,
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
        if (expression.includes('for (const selector of [s.identity, s.protected])')) {
          clearFieldsCalls += 1;
          const changed = scenario !== 'delayed-cleanup-hydration' || clearFieldsCalls >= 3;
          reply({result: {value: changed}});
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

    def test_browser_control_plane_projects_canonical_chrome_without_new_state(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(
                str(self.binary), port=9224, args=["--headless=new"], runtime_seconds=60
            )
        worker = started["worker"]
        control = worker["control_plane"]
        self.assertEqual(control["schema_version"], 1)
        self.assertEqual(control["authority"]["control_plane"], "grabowski")
        self.assertEqual(control["intent"]["effect_class"], "managed-runtime-process")
        self.assertEqual(control["adapter"]["id"], "chrome-cdp")
        self.assertEqual(control["adapter"]["protocol"], "cdp")
        self.assertTrue(control["adapter"]["implemented"])
        self.assertEqual(control["browser"]["family"], "chrome-stable")
        self.assertEqual(control["browser"]["selection_role"], "canonical-operator")
        self.assertEqual(control["endpoint"]["address"], "127.0.0.1")
        self.assertTrue(control["endpoint"]["loopback_only"])
        self.assertEqual(control["profile"]["mode"], "ephemeral")
        self.assertEqual(control["profile"]["scope_kind"], "worker-ephemeral")
        self.assertEqual(
            control["profile"]["identity_sha256"],
            workers._browser_profile_identity(worker["profile_path"]),
        )
        future = control["adapter"]["future_adapters"]
        self.assertEqual(future[0]["id"], "webdriver-bidi")
        self.assertFalse(future[0]["implemented"])

    def test_distinct_ephemeral_profiles_can_run_concurrently(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            first = workers.browser_start(
                str(self.binary), port=9240, runtime_seconds=60
            )["worker"]
            second = workers.browser_start(
                str(self.binary), port=9241, runtime_seconds=60
            )["worker"]
        self.assertNotEqual(first["worker_id"], second["worker_id"])
        self.assertNotEqual(first["profile_path"], second["profile_path"])
        self.assertEqual(first["control_plane"]["profile"]["mode"], "ephemeral")
        self.assertEqual(second["control_plane"]["profile"]["mode"], "ephemeral")
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{first['profile_path']}")["owner_id"],
            f"worker:{first['worker_id']}",
        )
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{second['profile_path']}")["owner_id"],
            f"worker:{second['worker_id']}",
        )

    def test_browser_start_routes_launch_through_adapter_contract(self) -> None:
        with patch.object(
            workers,
            "_browser_adapter_launch_argv",
            wraps=workers._browser_adapter_launch_argv,
        ) as launch_adapter, patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(
                str(self.binary), port=9242, args=["--headless=new"], runtime_seconds=60
            )
        launch_adapter.assert_called_once()
        call = launch_adapter.call_args
        self.assertEqual(call.args[0]["adapter_id"], "chrome-cdp")
        self.assertEqual(call.kwargs["port"], 9242)
        self.assertEqual(
            started["worker"]["control_plane"]["endpoint"],
            {"address": "127.0.0.1", "port": 9242, "loopback_only": True},
        )
        self.assertIn(
            "loopback-debugging",
            started["worker"]["control_plane"]["adapter"]["capabilities"],
        )

    def test_brave_uses_chromium_cdp_fallback_policy(self) -> None:
        brave = self.root / "brave-browser"
        brave.write_text("#!/bin/sh\nexit 0\n")
        brave.chmod(0o755)
        with patch.object(workers, "_executable", return_value=brave.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(brave), port=9227, runtime_seconds=60)
        control = started["worker"]["control_plane"]
        self.assertEqual(control["adapter"]["id"], "chromium-cdp")
        self.assertEqual(control["adapter"]["protocol"], "cdp")
        self.assertEqual(control["browser"]["family"], "brave")
        self.assertEqual(control["browser"]["selection_role"], "fallback-test")

    def test_chrome_for_testing_is_reproducible_test_only(self) -> None:
        policy = workers._browser_adapter_policy(
            "/opt/chrome-for-testing/chrome-linux64/chrome"
        )
        self.assertEqual(policy["family"], "chrome-for-testing")
        self.assertEqual(policy["adapter_id"], "chrome-cdp")
        self.assertEqual(policy["selection_role"], "reproducible-test")

    def test_non_chromium_browser_fails_closed_before_profile_creation(self) -> None:
        firefox = self.root / "firefox"
        firefox.write_text("#!/bin/sh\nexit 0\n")
        firefox.chmod(0o755)
        with patch.object(workers, "_executable", return_value=firefox.resolve()):
            with self.assertRaisesRegex(ValueError, "WebDriver BiDi is not implemented"):
                workers.browser_start(str(firefox), port=9228, runtime_seconds=60)
        self.assertFalse(workers.WORKER_STATE.exists())
        projected = workers._browser_adapter_policy(firefox, require_supported=False)
        self.assertFalse(projected["implemented"])
        self.assertEqual(projected["selection_role"], "unsupported")

    def test_same_persistent_profile_is_exclusive(self) -> None:
        profile_root = self.root / "browser-profiles"
        profile_root.mkdir()
        profile = profile_root / "github-auth"
        configured_roots = [str(profile_root)]
        with patch.object(workers.base, "_load_policy", return_value={}), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            first = workers.browser_start(
                str(self.binary),
                port=9230,
                persistent_profile=str(profile),
                runtime_seconds=60,
            )["worker"]
            with self.assertRaises(workers.resources.ResourceConflict):
                workers.browser_start(
                    str(self.binary),
                    port=9231,
                    persistent_profile=str(profile),
                    runtime_seconds=60,
                )
        profile_key = f"browser-profile:{profile}"
        self.assertEqual(
            workers.resources.inspect_resource(profile_key)["owner_id"],
            f"worker:{first['worker_id']}",
        )
        self.assertIsNone(workers.resources.inspect_resource("port:9231"))
        self.assertEqual(first["control_plane"]["profile"]["mode"], "persistent")
        self.assertEqual(
            first["control_plane"]["profile"]["scope_kind"],
            "explicit-auth-trust-scope",
        )

    def test_distinct_persistent_profiles_can_run_concurrently(self) -> None:
        profile_root = self.root / "browser-profiles"
        profile_root.mkdir()
        first_profile = profile_root / "github-auth"
        second_profile = profile_root / "n8n-auth"
        configured_roots = [str(profile_root)]
        with patch.object(workers.base, "_load_policy", return_value={}), patch.object(
            workers.base, "_profile_values", return_value=configured_roots
        ), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            first = workers.browser_start(
                str(self.binary),
                port=9232,
                persistent_profile=str(first_profile),
                runtime_seconds=60,
            )["worker"]
            second = workers.browser_start(
                str(self.binary),
                port=9233,
                persistent_profile=str(second_profile),
                runtime_seconds=60,
            )["worker"]
        self.assertNotEqual(first["worker_id"], second["worker_id"])
        self.assertNotEqual(
            first["control_plane"]["profile"]["identity_sha256"],
            second["control_plane"]["profile"]["identity_sha256"],
        )
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{first_profile}")["owner_id"],
            f"worker:{first['worker_id']}",
        )
        self.assertEqual(
            workers.resources.inspect_resource(f"browser-profile:{second_profile}")["owner_id"],
            f"worker:{second['worker_id']}",
        )

    def test_browser_audit_uses_hashed_profile_identity_only(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9234, runtime_seconds=60)
        worker = started["worker"]
        with patch.object(workers.base, "_append_audit") as append:
            workers._audit("browser-worker-start", started)
        audit = append.call_args.args[0]
        serialized = json.dumps(audit, sort_keys=True)
        self.assertNotIn(worker["profile_path"], serialized)
        control = audit["browser_control_plane"]
        self.assertEqual(control["adapter_id"], "chrome-cdp")
        self.assertEqual(control["protocol"], "cdp")
        self.assertEqual(control["profile_mode"], "ephemeral")
        self.assertEqual(
            control["profile_identity_sha256"],
            worker["control_plane"]["profile"]["identity_sha256"],
        )
        self.assertTrue(control["loopback_only"])

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

    def test_planned_runtime_limit_is_completed_and_releases_ephemeral_profile(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9224, runtime_seconds=60)
        worker = started["worker"]
        profile = Path(worker["profile_path"])
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainStatus=0\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=61000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1060), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(status["state"], "completed")
        self.assertEqual(status["last_observation"]["properties"]["Result"], "timeout")
        self.assertIsNone(workers.resources.inspect_resource("port:9224"))
        self.assertFalse(profile.exists())

    def test_timeout_before_planned_runtime_limit_is_failed(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9228, runtime_seconds=60)
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainStatus=0\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=60000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1100), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")

    def test_timeout_with_nonzero_exit_is_failed_after_runtime_limit(self) -> None:
        with patch.object(workers, "_now", return_value=1000), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.browser_start(str(self.binary), port=9229, runtime_seconds=60)
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainStatus=1\n"
                "ActiveEnterTimestampMonotonic=1000000\n"
                "ActiveExitTimestampMonotonic=61000000\n"
            )
        )
        with patch.object(workers, "_now", return_value=1060), patch.object(
            workers.operator, "_run", return_value=timeout_probe
        ):
            status = workers.worker_status(
                started["worker"]["worker_id"], expected_kind="browser"
            )
        self.assertEqual(status["state"], "failed")

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

    def test_stored_form_helper_flushes_receipt_before_bounded_exit(self) -> None:
        source = workers.BROWSER_FORM_NODE_SOURCE
        self.assertIn("const EXIT_FLUSH_TIMEOUT_MS = 1000;", source)
        self.assertIn("process.stdout.write(line, () => {", source)
        self.assertIn("const forcedExit = setTimeout(finish, EXIT_FLUSH_TIMEOUT_MS);", source)
        self.assertIn("process.exit(status);", source)

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

    def test_stored_form_helper_polls_until_form_contract_is_hydrated(self) -> None:
        execution, receipt = self._run_browser_form_node(
            "delayed-form-hydration", cleanup_only=False, action_mode="readiness"
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(receipt["result_code"], "ready")
        self.assertIs(receipt["fill_confirmed"], True)
        self.assertIs(receipt["cleaned"], True)

    def test_stored_form_helper_polls_cleanup_until_fields_are_hydrated(self) -> None:
        execution, receipt = self._run_browser_form_node("delayed-cleanup-hydration")
        self.assertEqual(execution.returncode, 0, execution.stderr)
        self.assertEqual(receipt["result_code"], "cleanup")
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


    def test_browser_prelaunch_failure_cleans_private_key_and_ephemeral_state(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers, "_write_config", side_effect=OSError("simulated config write failure")
        ):
            with self.assertRaisesRegex(OSError, "simulated config write failure"):
                workers.browser_start(str(self.binary), port=9225, runtime_seconds=60)
        self.assertIsNone(workers.resources.inspect_resource("port:9225"))
        instances = workers.WORKER_STATE / "instances"
        profiles = workers.WORKER_STATE / "profiles"
        self.assertEqual(list(instances.iterdir()) if instances.exists() else [], [])
        self.assertEqual(list(profiles.iterdir()) if profiles.exists() else [], [])


    def test_current_list_observes_stale_running_without_mutation(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9320, runtime_seconds=60)
        worker = started["worker"]
        record = workers._row(worker["worker_id"])
        config_path = Path(record["config_path"])
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe), patch.object(
            workers, "_update", side_effect=AssertionError("list must not persist")
        ), patch.object(
            workers, "_release", side_effect=AssertionError("list must not release")
        ), patch.object(
            workers, "_cleanup", side_effect=AssertionError("list must not cleanup")
        ):
            current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["view"], "current")
        self.assertEqual(current["count"], 0)
        self.assertEqual(current["observed_count"], 1)
        self.assertEqual(
            workers.resources.inspect_resource("port:9320")["owner_id"],
            f"worker:{worker['worker_id']}",
        )
        self.assertEqual(workers._row(worker["worker_id"])["state"], "running")
        self.assertTrue(config_path.exists())

        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(reconciled["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9320"))
        observation = reconciled["last_observation"]
        self.assertEqual(observation["terminalization"]["release"]["status"], "released")
        self.assertIn(
            str(config_path.parent),
            observation["terminalization"]["cleanup"]["preserved_evidence"],
        )
        with patch.object(workers, "_observe", side_effect=AssertionError("history must not probe")):
            history = workers.worker_list("browser", limit=10, view="history")
        self.assertEqual(history["count"], 1)
        self.assertEqual(history["workers"][0]["state"], "completed")
        self.assertFalse(history["workers"][0]["projection"]["fresh"])

    def test_list_missing_registry_does_not_create_state(self) -> None:
        self.assertFalse(workers.WORKER_STATE.exists())
        current = workers.worker_list("browser", limit=10)
        history = workers.worker_list("gui", limit=10, view="history")
        self.assertEqual(current["count"], 0)
        self.assertEqual(history["count"], 0)
        self.assertFalse(workers.WORKER_STATE.exists())
        self.assertFalse(workers.WORKER_DB.exists())

    def test_current_list_does_not_migrate_worker_database(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            workers.browser_start(str(self.binary), port=9323, runtime_seconds=60)
        with sqlite3.connect(workers.WORKER_DB) as connection:
            before = connection.execute(
                "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
            ).fetchall()
        before_bytes = workers.WORKER_DB.read_bytes()
        before_stat = workers.WORKER_DB.stat()
        before_entries = sorted(path.name for path in workers.WORKER_STATE.iterdir())
        observation = {
            "state": "running",
            "properties": {"LoadState": "loaded", "ActiveState": "active"},
            "probe": result(),
            "observed_at_unix": 223344,
        }
        with patch.object(workers, "_observe", return_value=observation):
            current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        with sqlite3.connect(workers.WORKER_DB) as connection:
            after = connection.execute(
                "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
            ).fetchall()
        after_stat = workers.WORKER_DB.stat()
        self.assertEqual(after, before)
        self.assertEqual(workers.WORKER_DB.read_bytes(), before_bytes)
        self.assertEqual(after_stat.st_mode, before_stat.st_mode)
        self.assertEqual(after_stat.st_size, before_stat.st_size)
        self.assertEqual(after_stat.st_mtime_ns, before_stat.st_mtime_ns)
        self.assertEqual(
            sorted(path.name for path in workers.WORKER_STATE.iterdir()),
            before_entries,
        )

    def test_current_list_surfaces_ambiguous_missing_unit_without_persisting(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9321, runtime_seconds=60)
        worker_id = started["worker"]["worker_id"]
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=\nExecMainStatus=\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        item = current["workers"][0]
        self.assertEqual(item["state"], "interrupted")
        self.assertEqual(item["projection"]["stored_state"], "running")
        self.assertFalse(item["projection"]["persisted_by_list"])
        self.assertEqual(item["projection"]["bucket"], "attention")
        self.assertEqual(item["projection"]["reason"], "systemd-observation-ambiguous")
        self.assertEqual(workers._row(worker_id)["state"], "running")
        self.assertIsNotNone(workers.resources.inspect_resource("port:9321"))
        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker_id, expected_kind="browser")
        self.assertEqual(reconciled["state"], "interrupted")
        self.assertIsNone(workers.resources.inspect_resource("port:9321"))

    def test_status_releases_only_exact_worker_owned_leases(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9322, runtime_seconds=60)
        worker = started["worker"]
        owner = f"worker:{worker['worker_id']}"
        profile_key = f"browser-profile:{worker['profile_path']}"
        workers.resources.release_resources(owner, ["port:9322"])
        workers.resources.acquire_resources(
            "foreign-owner",
            ["port:9322"],
            purpose="foreign replacement",
            ttl_seconds=60,
        )
        probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        release = reconciled["last_observation"]["terminalization"]["release"]
        self.assertEqual(release["status"], "partial")
        self.assertEqual(release["blocked"][0]["resource_key"], "port:9322")
        self.assertEqual(
            workers.resources.inspect_resource("port:9322")["owner_id"],
            "foreign-owner",
        )
        self.assertIsNone(workers.resources.inspect_resource(profile_key))

        current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        self.assertEqual(current["observed_count"], 0)
        self.assertEqual(
            current["workers"][0]["projection"]["reason"],
            "terminalization-incomplete",
        )
        self.assertFalse(current["workers"][0]["projection"]["fresh"])
        workers.resources.release_resources("foreign-owner", ["port:9322"])
        still_attention = workers.worker_list("browser", limit=10)
        self.assertEqual(still_attention["count"], 1)
        with patch.object(workers.operator, "_run", return_value=probe):
            workers.worker_status(worker["worker_id"], expected_kind="browser")
        final = workers.worker_list("browser", limit=10)
        self.assertEqual(final["count"], 0)
        self.assertIsNone(workers.resources.inspect_resource("port:9322"))

    def test_history_cursor_is_stable_for_same_second_records(self) -> None:
        created: list[str] = []
        with patch.object(workers, "_now", return_value=123456), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            for port in (9330, 9331, 9332):
                worker = workers.browser_start(
                    str(self.binary), port=port, runtime_seconds=60
                )["worker"]
                created.append(worker["worker_id"])
                workers._update(worker["worker_id"], "completed")
        with patch.object(workers, "_observe", side_effect=AssertionError("history must not probe")):
            first = workers.worker_list("browser", limit=2, view="history")
            second = workers.worker_list(
                "browser", limit=2, view="history", cursor=first["next_cursor"]
            )
        first_ids = [item["worker_id"] for item in first["workers"]]
        second_ids = [item["worker_id"] for item in second["workers"]]
        self.assertEqual(first["count"], 2)
        self.assertTrue(first["has_more"])
        self.assertEqual(second["count"], 1)
        self.assertFalse(second["has_more"])
        self.assertEqual(set(first_ids + second_ids), set(created))
        self.assertEqual(len(first_ids + second_ids), len(set(first_ids + second_ids)))

    def test_current_cursor_is_stable_and_reconciles_each_page(self) -> None:
        created: list[str] = []
        with patch.object(workers, "_now", return_value=222222), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            for port in (9340, 9341, 9342):
                worker = workers.browser_start(
                    str(self.binary), port=port, runtime_seconds=60
                )["worker"]
                created.append(worker["worker_id"])
        observation = {
            "state": "running",
            "properties": {"LoadState": "loaded", "ActiveState": "active"},
            "probe": result(),
            "observed_at_unix": 222223,
        }
        with patch.object(workers, "_observe", return_value=observation) as observe, patch.object(
            workers, "_update", side_effect=AssertionError("list must not persist")
        ), patch.object(
            workers, "_release", side_effect=AssertionError("list must not release")
        ), patch.object(
            workers, "_cleanup", side_effect=AssertionError("list must not cleanup")
        ):
            first = workers.worker_list("browser", limit=2)
            second = workers.worker_list(
                "browser", limit=2, cursor=first["next_cursor"]
            )
        ids = [item["worker_id"] for item in first["workers"] + second["workers"]]
        self.assertEqual(set(ids), set(created))
        self.assertEqual(first["observed_count"], 2)
        self.assertEqual(second["observed_count"], 1)
        self.assertEqual(observe.call_count, 3)
        self.assertTrue(all(item["projection"]["bucket"] == "active" for item in first["workers"] + second["workers"]))

    def test_gui_list_uses_shared_terminal_reconciliation(self) -> None:
        xvfb = self.root / "Xvfb-list"
        xvfb.write_text("#!/bin/sh\nexit 0\n")
        xvfb.chmod(0o755)
        with patch.object(workers.shutil, "which", return_value=str(xvfb)), patch.object(
            workers, "_executable", return_value=self.binary.resolve()
        ), patch.object(workers.operator, "_run", return_value=result()):
            started = workers.gui_start(
                str(self.binary), display_number=31, runtime_seconds=60
            )
        config_path = Path(workers._row(started["worker"]["worker_id"])["config_path"])
        probe = result(
            stdout=(
                "LoadState=not-found\nActiveState=inactive\nSubState=dead\n"
                "Result=success\nExecMainStatus=0\n"
            )
        )
        worker_id = started["worker"]["worker_id"]
        with patch.object(workers.operator, "_run", return_value=probe):
            current = workers.worker_list("gui", limit=10)
        self.assertEqual(current["count"], 0)
        self.assertIsNotNone(workers.resources.inspect_resource("display:31"))
        self.assertEqual(workers._row(worker_id)["state"], "running")
        with patch.object(workers.operator, "_run", return_value=probe):
            reconciled = workers.worker_status(worker_id, expected_kind="gui")
        self.assertEqual(reconciled["state"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("display:31"))
        self.assertTrue(config_path.exists())

    def test_stop_records_terminalization_and_preserves_manifest(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9350, runtime_seconds=60)
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        handle_key = config_path.parent / ".semantic-handle-key"
        self.assertTrue(handle_key.is_file())
        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        self.assertTrue(config_path.exists())
        self.assertFalse(handle_key.exists())
        self.assertIsNone(workers.resources.inspect_resource("port:9350"))
        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(str(handle_key), terminalization["cleanup"]["removed"])

    def test_stop_unlinks_semantic_handle_key_symlink_without_following_target(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9380, runtime_seconds=60)
        worker = started["worker"]
        config_path = Path(workers._row(worker["worker_id"])["config_path"])
        handle_key = config_path.parent / ".semantic-handle-key"
        target = self.root / "semantic-key-cleanup-target"
        target.write_text("preserve-me")
        handle_key.unlink()
        handle_key.symlink_to(target)

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")

        self.assertFalse(handle_key.exists())
        self.assertEqual(target.read_text(), "preserve-me")
        terminalization = stopped["worker"]["last_observation"]["terminalization"]
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIn(str(handle_key), terminalization["cleanup"]["removed"])

    def test_stopped_status_preserves_explicit_state_over_timeout_evidence(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9351, runtime_seconds=60)
        worker_id = started["worker"]["worker_id"]
        timeout_probe = result(
            stdout=(
                "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                "Result=timeout\nExecMainStatus=0\n"
            )
        )
        with patch.object(workers.operator, "_run", return_value=timeout_probe):
            failed = workers.worker_status(worker_id, expected_kind="browser")
        self.assertEqual(failed["state"], "failed")

        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker_id, expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        prior = stopped["worker"]["last_observation"]["prior_observation"]
        self.assertEqual(prior["state"], "failed")
        self.assertEqual(prior["properties"]["Result"], "timeout")

        with patch.object(
            workers, "_observe", side_effect=AssertionError("stopped status must not probe systemd")
        ):
            readback = workers.worker_status(worker_id, expected_kind="browser")
        self.assertEqual(readback["state"], "stopped")
        self.assertEqual(
            readback["last_observation"]["terminalization"]["release"]["status"],
            "already-absent",
        )
        self.assertEqual(
            readback["last_observation"]["prior_observation"]["properties"]["Result"],
            "timeout",
        )
        with patch.object(workers.operator, "_run", return_value=result()):
            repeated = workers.worker_stop(worker_id, expected_kind="browser")
        repeated_prior = repeated["worker"]["last_observation"]["prior_observation"]
        self.assertEqual(repeated_prior["state"], "failed")
        self.assertEqual(repeated_prior["properties"]["Result"], "timeout")
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)
        history = workers.worker_list("browser", limit=10, view="history")
        self.assertEqual(history["count"], 1)
        self.assertEqual(history["workers"][0]["state"], "stopped")

    def test_stopped_status_terminalizes_legacy_record_without_observation(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9353, runtime_seconds=60)
        worker = started["worker"]
        workers._update(worker["worker_id"], "stopped")

        with patch.object(
            workers, "_observe", side_effect=AssertionError("legacy stopped status must not probe systemd")
        ):
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(reconciled["state"], "stopped")
        terminalization = reconciled["last_observation"]["terminalization"]
        self.assertEqual(terminalization["release"]["status"], "released")
        self.assertEqual(terminalization["cleanup"]["status"], "completed")
        self.assertIsNone(workers.resources.inspect_resource("port:9353"))
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def test_stopped_status_retries_incomplete_terminalization_without_probe(self) -> None:
        with patch.object(workers, "_executable", return_value=self.binary.resolve()), patch.object(
            workers.operator, "_run", return_value=result()
        ):
            started = workers.browser_start(str(self.binary), port=9352, runtime_seconds=60)
        worker = started["worker"]
        owner = f"worker:{worker['worker_id']}"
        workers.resources.release_resources(owner, ["port:9352"])
        workers.resources.acquire_resources(
            "foreign-owner",
            ["port:9352"],
            purpose="foreign replacement",
            ttl_seconds=60,
        )
        with patch.object(workers.operator, "_run", return_value=result()):
            stopped = workers.worker_stop(worker["worker_id"], expected_kind="browser")
        self.assertEqual(stopped["worker"]["state"], "stopped")
        self.assertEqual(
            stopped["worker"]["last_observation"]["terminalization"]["release"]["status"],
            "partial",
        )
        current = workers.worker_list("browser", limit=10)
        self.assertEqual(current["count"], 1)
        self.assertEqual(
            current["workers"][0]["projection"]["reason"],
            "terminalization-incomplete",
        )

        workers.resources.release_resources("foreign-owner", ["port:9352"])
        with patch.object(
            workers, "_observe", side_effect=AssertionError("stopped retry must not probe systemd")
        ):
            reconciled = workers.worker_status(worker["worker_id"], expected_kind="browser")
        self.assertEqual(reconciled["state"], "stopped")
        self.assertEqual(workers.worker_list("browser", limit=10)["count"], 0)

    def _running_observation(self) -> dict[str, object]:
        return {
            "state": "running",
            "properties": {},
            "probe": result(),
            "observed_at_unix": 1,
        }

    def _semantic_state_payload(
        self,
        *,
        origin: str = "http://device.home.arpa",
        ready_state: str = "complete",
        title: str = "Example Domain",
        main_frame_id: str = "frame-1",
        loader_id: str = "loader-1",
        elements: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        if elements is None:
            elements = [
                {
                    "backend_node_id": "101",
                    "role": "button",
                    "name": "Target",
                }
            ]
        return {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "state": {
                "origin": origin,
                "ready_state": ready_state,
                "title": title,
                "main_frame_id": main_frame_id,
                "loader_id": loader_id,
                "elements": elements,
            },
        }

    def test_browser_semantic_snapshot_id_is_deterministic_and_dom_bound(self) -> None:
        handle_key = b"k" * 32
        state = workers._bounded_browser_state(
            {
                "origin": "http://device.home.arpa",
                "ready_state": "complete",
                "title": "Example",
                "main_frame_id": "frame-1",
                "loader_id": "loader-1",
                "elements": [
                    {
                        "backend_node_id": "101",
                        "role": "button",
                        "name": "Target",
                    }
                ],
            }
        )
        first = workers._browser_snapshot_id("worker-a", state, handle_key)
        second = workers._browser_snapshot_id("worker-a", state, handle_key)
        self.assertEqual(first, second)
        self.assertTrue(workers._is_browser_snapshot_id(first))
        self.assertTrue(first.startswith(workers.BROWSER_SNAPSHOT_ID_PREFIX))

        reloaded_state = {**state, "loader_id": "loader-2"}
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-a", reloaded_state, handle_key)
        )
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-b", state, handle_key)
        )
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-a", state, b"q" * 32)
        )
        changed_dom = {
            **state,
            "elements": [{**state["elements"][0], "name": "Changed target"}],
        }
        self.assertNotEqual(
            first, workers._browser_snapshot_id("worker-a", changed_dom, handle_key)
        )

    def test_browser_semantic_element_id_is_keyed_snapshot_and_worker_bound(self) -> None:
        handle_key = b"k" * 32
        state = workers._bounded_browser_state(
            self._semantic_state_payload()["state"]
        )
        snapshot_id = workers._browser_snapshot_id("worker-a", state, handle_key)
        element = state["elements"][0]
        first = workers._browser_element_id(
            "worker-a", snapshot_id, element, handle_key
        )
        second = workers._browser_element_id(
            "worker-a", snapshot_id, element, handle_key
        )
        self.assertEqual(first, second)
        self.assertTrue(workers._is_browser_element_id(first))
        self.assertTrue(first.startswith(workers.BROWSER_ELEMENT_ID_PREFIX))
        self.assertNotEqual(
            first,
            workers._browser_element_id(
                "worker-b", snapshot_id, element, handle_key
            ),
        )
        self.assertNotEqual(
            first,
            workers._browser_element_id(
                "worker-a", snapshot_id, element, b"q" * 32
            ),
        )
        changed_state = {
            **state,
            "elements": [{**element, "name": "Changed target"}],
        }
        changed_snapshot_id = workers._browser_snapshot_id(
            "worker-a", changed_state, handle_key
        )
        self.assertNotEqual(
            first,
            workers._browser_element_id(
                "worker-a",
                changed_snapshot_id,
                changed_state["elements"][0],
                handle_key,
            ),
        )

    def test_browser_semantic_handle_key_is_private_per_worker(self) -> None:
        worker_a = self._running_browser(port=9358)
        worker_b = self._running_browser(port=9359)
        record_a = workers._row(worker_a["worker_id"])
        record_b = workers._row(worker_b["worker_id"])
        key_a = workers._browser_semantic_handle_key(record_a)
        key_b = workers._browser_semantic_handle_key(record_b)
        self.assertEqual(len(key_a), 32)
        self.assertEqual(len(key_b), 32)
        self.assertNotEqual(key_a, key_b)
        key_path = Path(record_a["config_path"]).parent / ".semantic-handle-key"
        self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
        rendered = json.dumps(worker_a)
        self.assertNotIn(key_a.hex(), rendered)

    def test_browser_semantic_handle_key_rejects_hard_link(self) -> None:
        worker = self._running_browser(port=9356)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        linked_path = key_path.with_name(".semantic-handle-key-link")
        os.link(key_path, linked_path)
        try:
            with self.assertRaisesRegex(PermissionError, "metadata is unsafe"):
                workers._browser_semantic_handle_key(record)
        finally:
            linked_path.unlink()

    def test_browser_semantic_legacy_worker_without_handle_key_fails_before_transport(self) -> None:
        worker = self._running_browser(port=9357)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(workers, "_run_node_browser_semantic") as run:
            with self.assertRaisesRegex(
                RuntimeError, "predates semantic handle keys; start a fresh browser worker"
            ):
                workers.browser_semantic_observe(worker["worker_id"])
        run.assert_not_called()

    def test_browser_semantic_gateway_legacy_worker_preserves_fresh_worker_diagnostic(self) -> None:
        worker = self._running_browser(port=9376)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic"
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"], "observe"
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "fresh_worker_required")
        self.assertEqual(outcome["effect_state"], "not_applicable")
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "unavailable",
        )
        require_mutation.assert_not_called()
        run.assert_not_called()
        self.assertEqual(append_audit.call_count, 1)

    def test_browser_semantic_gateway_legacy_worker_act_is_not_outcome_unknown(self) -> None:
        worker = self._running_browser(port=9377)
        record = workers._row(worker["worker_id"])
        key_path = Path(record["config_path"]).parent / ".semantic-handle-key"
        key_path.unlink()
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        element_id = workers.BROWSER_ELEMENT_ID_PREFIX + "b" * 64
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic"
        ) as run, patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="scroll_into_view",
                element_id=element_id,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "fresh_worker_required")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(
            outcome["retry_readback"]["authoritative_readback_required"]
        )
        require_mutation.assert_called_once_with("browser_worker")
        run.assert_not_called()
        self.assertEqual(append_audit.call_count, 2)

    def test_browser_semantic_observe_bounds_and_redacts_element_projection(self) -> None:
        worker = self._running_browser(port=9360)
        raw_elements = [
            {
                "backend_node_id": str(index + 1),
                "role": "button",
                "name": ("  Target   " + str(index) + "  ") * 40,
                "selector": f"#target-{index}",
                "value": "credential-value-must-not-leak",
                "html": "<button>secret</button>",
            }
            for index in range(100)
        ]
        payload = self._semantic_state_payload(elements=raw_elements)
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(workers, "_update") as update, patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            observation = workers.browser_semantic_observe(worker["worker_id"])
        self.assertEqual(observation["schema_version"], 1)
        self.assertEqual(observation["worker_id"], worker["worker_id"])
        self.assertTrue(workers._is_browser_snapshot_id(observation["snapshot_id"]))
        self.assertEqual(observation["origin"], "http://device.home.arpa")
        self.assertEqual(observation["ready_state"], "complete")
        self.assertEqual(len(observation["elements"]), workers.BROWSER_MAX_ELEMENTS)
        for element in observation["elements"]:
            self.assertEqual(set(element), {"element_id", "role", "name"})
            self.assertTrue(workers._is_browser_element_id(element["element_id"]))
            self.assertLessEqual(len(element["role"]), workers.BROWSER_ELEMENT_ROLE_MAX)
            self.assertLessEqual(len(element["name"]), workers.BROWSER_ELEMENT_NAME_MAX)
        self.assertNotIn("main_frame_id", observation)
        self.assertNotIn("loader_id", observation)
        rendered = json.dumps(observation)
        for hidden_term in (
            "backend_node_id",
            "selector",
            "credential-value-must-not-leak",
            "<button>secret</button>",
            "Runtime.evaluate",
            "Accessibility.getFullAXTree",
            "DOM.resolveNode",
        ):
            self.assertNotIn(hidden_term, rendered)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")
        self.assertNotIn("selector", run.call_args.args[1])
        update.assert_not_called()

    def test_browser_semantic_act_rejects_stale_snapshot_before_effect(self) -> None:
        worker = self._running_browser(port=9361)
        initial_payload = self._semantic_state_payload(title="Before")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=initial_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        stale_snapshot_id = observation["snapshot_id"]
        element_id = observation["elements"][0]["element_id"]

        changed_payload = self._semantic_state_payload(title="After navigation")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=changed_payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                stale_snapshot_id,
                "scroll_into_view",
                element_id=element_id,
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertIsNone(outcome["post_action_snapshot_id"])
        self.assertEqual(outcome["requested_snapshot_id"], stale_snapshot_id)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")

    def test_browser_semantic_act_rejects_semantic_dom_drift_before_effect(self) -> None:
        worker = self._running_browser(port=9362)
        initial_payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=initial_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        changed_payload = self._semantic_state_payload(
            elements=[
                {
                    "backend_node_id": "101",
                    "role": "button",
                    "name": "Target changed in place",
                }
            ]
        )
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=changed_payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        run.assert_called_once()

    def test_browser_semantic_act_rejects_tampered_element_handle_before_effect(self) -> None:
        worker = self._running_browser(port=9363)
        payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        element_id = observation["elements"][0]["element_id"]
        replacement = "0" if element_id[-1] != "0" else "1"
        tampered = element_id[:-1] + replacement
        self.assertTrue(workers._is_browser_element_id(tampered))
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "scroll_into_view",
                element_id=tampered,
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "element_contract")
        self.assertEqual(outcome["requested_element_id"], tampered)
        run.assert_called_once()

    def test_browser_semantic_act_rejects_cross_worker_element_replay(self) -> None:
        worker_a = self._running_browser(port=9364)
        worker_b = self._running_browser(port=9365)
        payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation_a = workers.browser_semantic_observe(worker_a["worker_id"])
            observation_b = workers.browser_semantic_observe(worker_b["worker_id"])
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker_b["worker_id"],
                observation_b["snapshot_id"],
                "scroll_into_view",
                element_id=observation_a["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "element_contract")
        run.assert_called_once()

    def test_browser_semantic_act_local_ui_scroll_uses_only_opaque_element_id(self) -> None:
        worker = self._running_browser(port=9366)
        pre_payload = self._semantic_state_payload(title="Steady")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=pre_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        snapshot_id = observation["snapshot_id"]
        element_id = observation["elements"][0]["element_id"]

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[pre_payload, pre_payload],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                snapshot_id,
                "scroll_into_view",
                element_id=element_id,
            )
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["result_code"], "ok")
        self.assertEqual(outcome["effect_class"], "local_ui")
        self.assertEqual(outcome["requested_element_id"], element_id)
        self.assertEqual(outcome["pre_action_snapshot_id"], snapshot_id)
        self.assertEqual(outcome["post_action_snapshot_id"], snapshot_id)
        self.assertIn("credential_handling_safety", outcome["does_not_establish"])
        self.assertEqual(run.call_count, 2)
        effect_request = run.call_args_list[1].args[1]
        self.assertEqual(effect_request["op"], "scroll_into_view")
        self.assertNotIn("selector", effect_request)
        self.assertEqual(
            effect_request["expected_element"],
            workers._bounded_browser_state(pre_payload["state"])["elements"][0],
        )
        self.assertEqual(
            effect_request["expected_state"],
            workers._bounded_browser_state(pre_payload["state"]),
        )

    def test_browser_semantic_act_maps_adapter_element_toctou_to_stale_snapshot(self) -> None:
        worker = self._running_browser(port=9367)
        pre_payload = self._semantic_state_payload(title="Steady")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=pre_payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        stale_guard_payload = {
            "schema_version": 1,
            "ok": False,
            "result_code": "stale-snapshot",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[pre_payload, stale_guard_payload],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[1].args[1]["expected_element"],
            workers._bounded_browser_state(pre_payload["state"])["elements"][0],
        )

    def test_browser_semantic_node_revalidates_element_without_public_selector(self) -> None:
        source = workers.BROWSER_SEMANTIC_NODE_SOURCE
        self.assertIn("Accessibility.getFullAXTree", source)
        self.assertIn("Accessibility.getPartialAXTree", source)
        self.assertIn("DOM.resolveNode", source)
        self.assertIn("Runtime.callFunctionOn", source)
        self.assertIn("Runtime.releaseObject", source)
        self.assertIn("Number.isSafeInteger", source)
        self.assertNotIn("document.querySelector", source)
        verify = "const objectId = await verifyElementImmediately(expectedElement);"
        effect = "effect = await call('Runtime.callFunctionOn'"
        release = "await call('Runtime.releaseObject', {objectId});"
        self.assertIn(verify, source)
        self.assertIn(effect, source)
        self.assertIn(release, source)
        self.assertLess(source.index(verify), source.index(effect))
        self.assertLess(source.index(effect), source.index(release))

    def test_browser_semantic_act_read_state_performs_no_separate_effect_call(self) -> None:
        worker = self._running_browser(port=9368)
        payload = self._semantic_state_payload(title="Read only")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        snapshot_id = observation["snapshot_id"]

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"], snapshot_id, "read_state"
            )
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["effect_class"], "read")
        self.assertIsNone(outcome["requested_element_id"])
        self.assertEqual(outcome["post_action_snapshot_id"], snapshot_id)
        run.assert_called_once()

    def test_browser_semantic_navigate_requires_a_conservative_target(self) -> None:
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        invalid_targets = (
            None,
            "",
            " example.com",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://user:password@example.invalid/private",
            "https://example.invalid/path\nnext",
            "https://example.invalid:0/",
        )
        for target in invalid_targets:
            with self.subTest(target=target), self.assertRaises(ValueError):
                workers.browser_semantic_act(
                    "0" * 20,
                    snapshot_id,
                    "navigate",
                    navigation_target=target,
                )

    def test_browser_semantic_adapter_selects_chrome_cdp_boundary(self) -> None:
        worker = self._running_browser(port=9382)
        record = workers._row(worker["worker_id"])

        adapter = workers._browser_semantic_adapter(record, timeout_seconds=10)

        self.assertIsInstance(adapter, workers.CDPAdapter)
        self.assertIsInstance(adapter, workers.ChromeCDPAdapter)

    def test_browser_semantic_navigate_uses_adapter_ack_then_fresh_readback(self) -> None:
        worker = self._running_browser(port=9378)
        before = self._semantic_state_payload(title="Before", loader_id="loader-before")
        after = self._semantic_state_payload(
            origin="https://example.invalid",
            title="After",
            loader_id="loader-after",
        )
        navigate_ack = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, navigate_ack, after],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "navigate",
                navigation_target="https://example.invalid/path?view=semantic",
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["result_code"], "ok")
        self.assertEqual(outcome["effect_class"], "local_ui")
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertEqual(outcome["pre_action_snapshot_id"], observation["snapshot_id"])
        self.assertNotEqual(
            outcome["post_action_snapshot_id"], observation["snapshot_id"]
        )
        self.assertEqual(
            outcome["post_action_snapshot_id"], outcome["observation"]["snapshot_id"]
        )
        self.assertEqual(
            [call.args[1]["op"] for call in run.call_args_list],
            ["read_state", "navigate", "read_state"],
        )
        self.assertEqual(
            run.call_args_list[1].args[1]["navigation_target"],
            "https://example.invalid/path?view=semantic",
        )
        self.assertNotIn("navigation_target", json.dumps(outcome, sort_keys=True))

    def test_browser_semantic_navigate_ack_without_readback_fails_closed(self) -> None:
        worker = self._running_browser(port=9379)
        before = self._semantic_state_payload(title="Before")
        navigate_ack = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "state": None,
        }
        observation_failure = {
            "schema_version": 1,
            "ok": False,
            "result_code": "transport",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, navigate_ack, observation_failure],
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "navigate",
                navigation_target="https://example.invalid/",
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "observation_failed")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertIsNone(outcome["post_action_snapshot_id"])
        self.assertEqual(outcome["observation"]["snapshot_id"], observation["snapshot_id"])
        self.assertEqual(run.call_count, 3)

    def test_browser_semantic_navigate_error_text_is_unknown_with_fresh_readback(self) -> None:
        worker = self._running_browser(port=9380)
        before = self._semantic_state_payload(title="Before")
        after = self._semantic_state_payload(title="Observed after failure")
        navigation_error = {
            "schema_version": 1,
            "ok": False,
            "result_code": "navigation-error",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, navigation_error, after],
        ):
            outcome = workers.browser_semantic_act(
                worker["worker_id"],
                observation["snapshot_id"],
                "navigate",
                navigation_target="https://example.invalid/",
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "navigation_failed")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertIsNotNone(outcome["post_action_snapshot_id"])
        self.assertEqual(
            outcome["post_action_snapshot_id"], outcome["observation"]["snapshot_id"]
        )

    def test_browser_semantic_node_navigate_uses_page_navigate_and_error_text(self) -> None:
        source = workers.BROWSER_SEMANTIC_NODE_SOURCE
        self.assertIn("await call('Page.navigate'", source)
        self.assertIn("request.navigation_target", source)
        self.assertIn("navigation.errorText", source)
        self.assertNotIn("location.assign", source)
        self.assertNotIn("window.location", source)

    def test_browser_semantic_act_rejects_unsupported_action_kind(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported browser action kind"):
            workers.browser_semantic_act(
                "0" * 20,
                workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64,
                "not_supported",
            )

    def test_browser_semantic_act_fails_closed_for_unimplemented_effect_classes(self) -> None:
        worker = self._running_browser(port=9369)
        payload = self._semantic_state_payload(title="Unimplemented")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        snapshot_id = observation["snapshot_id"]

        fake_catalog = dict(workers.BROWSER_ACTION_CATALOG)
        fake_catalog["submit_generic"] = {
            "effect_class": "external_mutation",
            "requires_element": False,
        }
        with patch.object(workers, "BROWSER_ACTION_CATALOG", fake_catalog), patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run:
            outcome = workers.browser_semantic_act(
                worker["worker_id"], snapshot_id, "submit_generic"
            )
        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "effect_not_implemented")
        run.assert_called_once()
        self.assertEqual(run.call_args.args[1]["op"], "read_state")

    def test_browser_semantic_gateway_observe_exposes_bounded_name_but_audit_does_not(self) -> None:
        worker = self._running_browser(port=9370)
        accessibility_name = "Transfer all funds " + "x" * 200
        payload = self._semantic_state_payload(
            origin="https://user:password@example.invalid/private?token=secret",
            title="Private account dashboard",
            elements=[
                {
                    "backend_node_id": "101",
                    "role": "button",
                    "name": accessibility_name,
                    "selector": "#dangerous-private-selector",
                }
            ],
        )
        with patch.object(
            workers.operator, "_require_operator_capability"
        ) as require_capability, patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ), patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            result_payload = workers.grabowski_browser_worker_semantic(
                worker["worker_id"], "observe"
            )

        self.assertTrue(result_payload["ok"])
        self.assertEqual(result_payload["operation"], "observe")
        self.assertEqual(result_payload["effect_class"], "read")
        self.assertFalse(result_payload["retry_readback"]["retry_authorized"])
        self.assertEqual(
            result_payload["retry_readback"]["authoritative_readback_state"],
            "authoritative_fresh_observation",
        )
        self.assertEqual(
            set(result_payload["observation"]["elements"][0]),
            {"element_id", "role", "name"},
        )
        self.assertEqual(
            result_payload["observation"]["elements"][0]["name"],
            accessibility_name[: workers.BROWSER_ELEMENT_NAME_MAX],
        )
        self.assertLessEqual(
            len(result_payload["observation"]["elements"][0]["name"]),
            workers.BROWSER_ELEMENT_NAME_MAX,
        )
        require_capability.assert_called_with("browser_worker")
        require_mutation.assert_not_called()
        self.assertTrue(
            result_payload["semantic_catalog"]["intents"]["navigate"]
            ["requires_navigation_target"]
        )
        for effect_class in (
            "reversible_external",
            "external_mutation",
            "high_impact",
        ):
            effect = result_payload["semantic_catalog"]["effect_classes"][
                effect_class
            ]
            self.assertEqual(effect["admission"], "fail_closed")
            self.assertFalse(effect["ambiguous_outcome"]["retry_authorized"])
            self.assertTrue(
                effect["ambiguous_outcome"]["authoritative_readback_required"]
            )
            self.assertFalse(
                effect["ambiguous_outcome"]["readback_grants_retry_authority"]
            )

        rendered = json.dumps(result_payload, sort_keys=True)
        audit_rendered = json.dumps(append_audit.call_args.args[0], sort_keys=True)
        for forbidden in (
            "password",
            "token=secret",
            "Private account dashboard",
            "#dangerous-private-selector",
            "backend_node_id",
            "Runtime.evaluate",
            "Accessibility.getFullAXTree",
        ):
            self.assertNotIn(forbidden, rendered)
            self.assertNotIn(forbidden, audit_rendered)
        self.assertIn(accessibility_name[:160], rendered)
        self.assertNotIn(accessibility_name[:160], audit_rendered)
        self.assertNotIn('"name"', audit_rendered)
        self.assertEqual(append_audit.call_count, 1)
        audit_record = append_audit.call_args.args[0]
        self.assertEqual(audit_record["operation"], "browser-semantic-outcome")
        self.assertEqual(audit_record["worker_id"], worker["worker_id"])
        self.assertEqual(audit_record["intent"], "observe")
        self.assertEqual(audit_record["effect_class"], "read")
        self.assertTrue(audit_record["ok"])
        self.assertEqual(audit_record["result_code"], "ok")
        self.assertFalse(audit_record["retry_authorized"])
        self.assertEqual(result_payload["audit"]["outcome"]["record_sha256"], "a" * 64)

    def test_browser_semantic_gateway_act_preserves_post_action_readback(self) -> None:
        worker = self._running_browser(port=9371)
        payload = self._semantic_state_payload(title="Private title")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[payload, payload],
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["effect_class"], "local_ui")
        self.assertEqual(outcome["effect_state"], "observed")
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "authoritative_post_action_observation",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(outcome["retry_readback"]["readback_grants_retry_authority"])
        self.assertNotIn("title", json.dumps(outcome))
        require_mutation.assert_called_once_with("browser_worker")
        self.assertEqual(append_audit.call_count, 2)
        audit_records = json.dumps(
            [call.args[0] for call in append_audit.call_args_list], sort_keys=True
        )
        self.assertNotIn('"name"', audit_records)
        self.assertNotIn("Target", audit_records)
        self.assertNotIn("Private title", audit_records)
        self.assertEqual(
            [call.args[0]["operation"] for call in append_audit.call_args_list],
            ["browser-semantic-intent", "browser-semantic-outcome"],
        )
        self.assertEqual(outcome["audit"]["intent"]["record_sha256"], "a" * 64)
        self.assertEqual(outcome["audit"]["outcome"]["record_sha256"], "b" * 64)

    def test_browser_semantic_gateway_navigate_redacts_target_and_requires_readback(self) -> None:
        worker = self._running_browser(port=9381)
        before = self._semantic_state_payload(title="Before", loader_id="loader-before")
        after = self._semantic_state_payload(title="After", loader_id="loader-after")
        navigate_ack = {
            "schema_version": 1,
            "ok": True,
            "result_code": "ok",
            "state": None,
        }
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=before
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])

        navigation_target = "https://example.invalid/private?token=must-not-leak"
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers,
            "_run_node_browser_semantic",
            side_effect=[before, navigate_ack, after],
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, "b" * 64],
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="navigate",
                navigation_target=navigation_target,
            )

        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["intent"], "navigate")
        self.assertEqual(outcome["effect_class"], "local_ui")
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "authoritative_post_action_observation",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertFalse(outcome["retry_readback"]["readback_grants_retry_authority"])
        self.assertEqual(
            outcome["observation"]["snapshot_id"], outcome["post_action_snapshot_id"]
        )
        require_mutation.assert_called_once_with("browser_worker")
        rendered = json.dumps(outcome, sort_keys=True)
        audit_rendered = json.dumps(
            [call.args[0] for call in append_audit.call_args_list], sort_keys=True
        )
        self.assertNotIn(navigation_target, rendered)
        self.assertNotIn("must-not-leak", rendered)
        self.assertNotIn(navigation_target, audit_rendered)
        self.assertNotIn("must-not-leak", audit_rendered)

    def test_browser_semantic_gateway_stale_snapshot_returns_fresh_safe_handles(self) -> None:
        worker = self._running_browser(port=9372)
        initial = self._semantic_state_payload(title="Before")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=initial
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        changed = self._semantic_state_payload(title="After private navigation")
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ), patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=changed
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ):
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="scroll_into_view",
                element_id=observation["elements"][0]["element_id"],
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "stale_snapshot")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertNotEqual(
            outcome["observation"]["snapshot_id"], observation["snapshot_id"]
        )
        self.assertEqual(
            outcome["retry_readback"]["authoritative_readback_state"],
            "pre_action_observation_only",
        )
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertNotIn("After private navigation", json.dumps(outcome))
        run.assert_called_once()

    def test_browser_semantic_gateway_external_effects_remain_fail_closed(self) -> None:
        worker = self._running_browser(port=9373)
        payload = self._semantic_state_payload()
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            observation = workers.browser_semantic_observe(worker["worker_id"])
        fake_catalog = dict(workers.BROWSER_ACTION_CATALOG)
        fake_catalog["submit_generic"] = {
            "effect_class": "external_mutation",
            "requires_element": False,
        }
        with patch.object(
            workers, "BROWSER_ACTION_CATALOG", fake_catalog
        ), patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ) as require_mutation, patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ) as run, patch.object(
            workers.base, "_append_audit_with_digest", return_value="a" * 64
        ) as append_audit:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=observation["snapshot_id"],
                action_kind="submit_generic",
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "effect_not_implemented")
        self.assertEqual(outcome["effect_contract"]["admission"], "fail_closed")
        self.assertFalse(
            outcome["effect_contract"]["ambiguous_outcome"]["retry_authorized"]
        )
        self.assertTrue(
            outcome["effect_contract"]["ambiguous_outcome"][
                "authoritative_readback_required"
            ]
        )
        require_mutation.assert_not_called()
        run.assert_called_once()
        self.assertEqual(append_audit.call_count, 1)

    def test_browser_semantic_gateway_intent_audit_failure_blocks_effect(self) -> None:
        worker = self._running_browser(port=9374)
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        element_id = workers.BROWSER_ELEMENT_ID_PREFIX + "b" * 64
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=OSError("audit unavailable"),
        ), patch.object(workers, "browser_semantic_act") as semantic_act:
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="scroll_into_view",
                element_id=element_id,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "audit_unavailable")
        self.assertEqual(outcome["effect_state"], "not_started")
        self.assertFalse(outcome["audit"]["intent"]["recorded"])
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        semantic_act.assert_not_called()

    def test_browser_semantic_gateway_ambiguous_effect_and_audit_failure_forbid_retry(self) -> None:
        worker = self._running_browser(port=9375)
        snapshot_id = workers.BROWSER_SNAPSHOT_ID_PREFIX + "a" * 64
        element_id = workers.BROWSER_ELEMENT_ID_PREFIX + "b" * 64
        with patch.object(
            workers.operator, "_require_operator_capability"
        ), patch.object(
            workers.operator, "_require_operator_mutation"
        ), patch.object(
            workers.base,
            "_append_audit_with_digest",
            side_effect=["a" * 64, OSError("outcome audit unavailable")],
        ), patch.object(
            workers, "browser_semantic_act", side_effect=RuntimeError("lost response")
        ):
            outcome = workers.grabowski_browser_worker_semantic(
                worker["worker_id"],
                "act",
                snapshot_id=snapshot_id,
                action_kind="scroll_into_view",
                element_id=element_id,
            )

        self.assertFalse(outcome["ok"])
        self.assertEqual(outcome["result_code"], "outcome_unknown")
        self.assertEqual(outcome["effect_state"], "unknown")
        self.assertTrue(outcome["audit"]["intent"]["recorded"])
        self.assertFalse(outcome["audit"]["outcome"]["recorded"])
        self.assertFalse(outcome["retry_readback"]["retry_authorized"])
        self.assertTrue(
            outcome["retry_readback"]["authoritative_readback_required"]
        )
        self.assertFalse(
            outcome["retry_readback"]["readback_grants_retry_authority"]
        )
        self.assertEqual(
            outcome["retry_readback"]["next_action_after_ambiguous_effect"],
            "perform_authoritative_readback_then_form_a_new_explicit_intent",
        )

    def test_browser_semantic_contract_does_not_change_stored_form_action_safety(self) -> None:
        worker = self._running_browser(port=9366)
        payload = self._semantic_state_payload(title="Unrelated")
        with patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(
            workers, "_run_node_browser_semantic", return_value=payload
        ):
            workers.browser_semantic_observe(worker["worker_id"])

        with patch.object(
            workers,
            "_canonical_local_origin",
            return_value=("http://device.home.arpa", "b" * 64, ["192.168.1.1"]),
        ), patch.object(
            workers, "_observe", return_value=self._running_observation()
        ), patch.object(workers, "_run_node_form_action") as action:
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

        public_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]
        with patch.object(workers.socket, "getaddrinfo", return_value=public_answer):
            with self.assertRaisesRegex(PermissionError, "outside local"):
                workers._canonical_local_origin("http://example.invalid")

        signature = inspect.signature(workers.browser_stored_form_action)
        self.assertIn("confirmation", signature.parameters)
        self.assertNotIn("snapshot_id", signature.parameters)
        self.assertEqual(len(workers.BROWSER_FORM_RESULT_CODES), 13)

    def test_worker_list_cursor_is_bound_to_kind_and_view(self) -> None:
        with self.assertRaisesRegex(ValueError, "bound to another worker view"):
            workers.worker_list(
                "gui",
                view="history",
                cursor="browser:history:1:" + "0" * 20,
            )

if __name__ == "__main__":
    unittest.main()

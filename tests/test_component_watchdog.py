import hashlib
import itertools
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "component_watchdog.py"
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

spec = importlib.util.spec_from_file_location("component_watchdog_test", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("component watchdog could not be loaded")
watchdog = importlib.util.module_from_spec(spec)
sys.modules["component_watchdog_test"] = watchdog
spec.loader.exec_module(watchdog)

HEALTH_PAYLOAD = {"healthy": True, "audit_valid": True}
BOOT_ID = "11111111-2222-3333-8444-555555555555"


def fake_stdio_server_code(**config: object) -> str:
    encoded = json.dumps(config, separators=(",", ":"))
    return f'''import json
import sys
import time

config = json.loads({encoded!r})
log_path = config.get("log_path")

def record(method):
    if log_path:
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(str(method) + "\\n")

def emit(message):
    print(json.dumps(message, separators=(",", ":")), flush=True)

if config.get("exit_early"):
    raise SystemExit(7)

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    record(method)
    if method == "initialize":
        if config.get("sleep_initialize"):
            time.sleep(float(config["sleep_initialize"]))
        if config.get("malformed_json"):
            print("{{", flush=True)
            continue
        if config.get("oversize"):
            print("x" * {watchdog.MCP_MAX_RESPONSE_BYTES + 1}, flush=True)
            continue
        if config.get("unrelated_before_initialize"):
            emit({{"jsonrpc": "2.0", "method": "notifications/message", "params": {{}}}})
        if config.get("initialize_error"):
            emit({{"jsonrpc": "2.0", "id": message["id"], "error": {{"code": -1, "message": "no"}}}})
            continue
        result = {{
            "protocolVersion": config.get("protocol_version", "2025-11-25"),
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "stub", "version": "1"}},
        }}
        if config.get("bad_initialize_shape"):
            result.pop("serverInfo")
        emit({{"jsonrpc": "2.0", "id": message["id"], "result": result}})
    elif method == "notifications/initialized":
        continue
    elif method == "tools/call":
        if config.get("sleep_tool"):
            time.sleep(float(config["sleep_tool"]))
        if config.get("tool_rpc_error"):
            emit({{"jsonrpc": "2.0", "id": message["id"], "error": {{"code": -32603, "message": "failed"}}}})
            continue
        payload = config.get("tool_payload", {json.dumps(HEALTH_PAYLOAD)!r})
        if isinstance(payload, str):
            payload = json.loads(payload)
        result = {{
            "content": [{{"type": "text", "text": json.dumps(payload)}}],
            "isError": config.get("tool_error", False),
        }}
        if not config.get("omit_structured"):
            result["structuredContent"] = payload
        emit({{"jsonrpc": "2.0", "id": message["id"], "result": result}})

if config.get("linger_on_eof"):
    time.sleep(float(config.get("linger_seconds", 5)))
'''


class McpLifecycleProbeTests(unittest.TestCase):
    def probe(self, timeout: float = 2.0, **config: object) -> str | None:
        return watchdog.mcp_stdio_probe(
            sys.executable,
            ["-u", "-c", fake_stdio_server_code(**config)],
            timeout,
        )

    def test_full_lifecycle_and_no_tool_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "methods.log"
            self.assertIsNone(self.probe(log_path=str(log_path)))
            self.assertEqual(
                ["initialize", "notifications/initialized", "tools/call"],
                log_path.read_text(encoding="utf-8").splitlines(),
            )

    def test_unrelated_jsonrpc_message_is_ignored(self) -> None:
        self.assertIsNone(self.probe(unrelated_before_initialize=True))

    def test_initialize_error_and_invalid_shape_fail(self) -> None:
        self.assertEqual(
            "mcp-initialize-invalid", self.probe(initialize_error=True)
        )
        self.assertEqual(
            "mcp-initialize-shape-invalid",
            self.probe(bad_initialize_shape=True),
        )

    def test_tool_errors_fail(self) -> None:
        self.assertEqual("mcp-tool-error", self.probe(tool_error=True))
        self.assertEqual(
            "mcp-tool-call-invalid", self.probe(tool_rpc_error=True)
        )

    def test_tool_payload_without_health_flag_fails(self) -> None:
        self.assertEqual(
            "mcp-tool-shape-invalid",
            self.probe(tool_payload={"status": "ok"}),
        )

    def test_runtime_unhealthy_is_not_a_green_probe(self) -> None:
        self.assertEqual(
            "mcp-runtime-unhealthy",
            self.probe(tool_payload={"healthy": False}),
        )

    def test_text_content_fallback_without_structured_content(self) -> None:
        self.assertIsNone(self.probe(omit_structured=True))

    def test_oversized_and_malformed_responses_are_rejected(self) -> None:
        self.assertEqual("mcp-response-too-large", self.probe(oversize=True))
        self.assertEqual("mcp-json-invalid", self.probe(malformed_json=True))

    def test_timeout_and_early_process_exit_are_reported(self) -> None:
        self.assertEqual(
            "mcp-stdio-timeout",
            self.probe(timeout=0.1, sleep_initialize=1.0),
        )
        self.assertEqual(
            "mcp-stdio-process-exited", self.probe(exit_early=True)
        )

    def test_missing_executable_is_reported(self) -> None:
        self.assertEqual(
            "mcp-stdio-start-failed",
            watchdog.mcp_stdio_probe(
                "/definitely/missing/grabowski-python", [], 0.1
            ),
        )

    def test_nonzero_or_hanging_shutdown_invalidates_success(self) -> None:
        with patch.object(watchdog, "MCP_STDIO_SHUTDOWN_TIMEOUT", 0.05):
            self.assertEqual(
                "mcp-stdio-cleanup-failed",
                self.probe(linger_on_eof=True, linger_seconds=5),
            )

    def test_live_healthy_isolated_runtime_failure_is_diagnostic_only(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "123",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=42),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "operator_identity_ok", return_value=True),
            patch.object(watchdog, "mcp_http_probe", return_value=None),
            patch.object(
                watchdog,
                "mcp_stdio_probe_from_runtime",
                return_value="mcp-runtime-unhealthy",
            ),
        ):
            result = watchdog.probe_component(
                component="operator",
                service="grabowski-operator.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url="http://127.0.0.1:18080/healthz",
                ready_url="http://127.0.0.1:18080/readyz",
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("healthy", result.status)
        self.assertEqual(
            ("isolated-probe-mcp-runtime-unhealthy",), result.reasons
        )

    def test_runtime_probe_rejects_invalid_module_or_root(self) -> None:
        with self.assertRaisesRegex(watchdog.WatchdogError, "runtime-root"):
            watchdog.mcp_stdio_probe_from_runtime(
                Path("/definitely/missing"), "grabowski_operator", 1
            )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / ".venv/bin").mkdir(parents=True)
            executable = root / ".venv/bin/python"
            executable.symlink_to(sys.executable)
            with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-mcp-module"):
                watchdog.mcp_stdio_probe_from_runtime(root, "../bad", 1)


class ControlPlanePollProbeTests(unittest.TestCase):
    def readiness_probe(
        self,
        *,
        boot_id: str = BOOT_ID,
        pid: int = 321,
        start_ticks: int = 77,
        age_seconds: float = 120.0,
    ) -> object:
        return watchdog.ProbeResult(
            "indeterminate",
            ("readiness-failed",),
            pid=pid,
            age_seconds=age_seconds,
            start_ticks=start_ticks,
            boot_id=boot_id,
        )

    def tunnel_identity(
        self,
        *,
        boot_id: str = BOOT_ID,
        pid: int = 321,
        start_ticks: int = 77,
        age_seconds: float = 120.0,
    ) -> object:
        return watchdog.TunnelProcessIdentity(
            boot_id,
            pid,
            start_ticks,
            age_seconds,
        )

    def classify(
        self,
        probe: object,
        state: object,
        *,
        dependency_failure: str | None,
        identity: object | None = None,
        identity_failure: str | None = None,
    ) -> tuple[object, object]:
        stable_identity = self.tunnel_identity() if identity is None else identity
        with (
            patch.object(
                watchdog,
                "mcp_http_probe",
                return_value=dependency_failure,
            ),
            patch.object(
                watchdog,
                "tunnel_service_process_identity",
                return_value=(stable_identity, identity_failure),
            ),
        ):
            return watchdog.classify_tunnel_readiness_dependency(
                probe,
                state,
                service=watchdog.DEFAULT_TUNNEL_SERVICE,
                profile=watchdog.DEFAULT_PROFILE,
                startup_grace=20,
                mcp_url=watchdog.DEFAULT_MCP_URL,
                timeout=2,
            )

    def test_recent_control_plane_poll_is_healthy(self) -> None:
        metrics = (
            "# TYPE commands_poll_last_successful_timestamp_seconds gauge\n"
            "commands_poll_last_successful_timestamp_seconds{otel_scope_name=\"controlplane\"} 1000\n"
        )
        with patch.object(watchdog, "get_bounded_text", return_value=metrics):
            self.assertIsNone(
                watchdog.control_plane_poll_probe(
                    watchdog.DEFAULT_METRICS_URL, 2, 90, now=1050
                )
            )

    def test_stale_missing_and_unavailable_control_plane_poll_fail(self) -> None:
        stale = "commands_poll_last_successful_timestamp_seconds 1000\n"
        with patch.object(watchdog, "get_bounded_text", return_value=stale):
            self.assertEqual(
                "control-plane-poll-stale",
                watchdog.control_plane_poll_probe(
                    watchdog.DEFAULT_METRICS_URL, 2, 90, now=1091
                ),
            )
        with patch.object(watchdog, "get_bounded_text", return_value="# no sample\n"):
            self.assertEqual(
                "control-plane-poll-missing",
                watchdog.control_plane_poll_probe(
                    watchdog.DEFAULT_METRICS_URL, 2, 90, now=1091
                ),
            )
        with patch.object(watchdog, "get_bounded_text", return_value=None):
            self.assertEqual(
                "control-plane-metrics-unavailable",
                watchdog.control_plane_poll_probe(
                    watchdog.DEFAULT_METRICS_URL, 2, 90, now=1091
                ),
            )

    def test_tunnel_identity_reprobe_requires_stable_systemd_process(self) -> None:
        running = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "321",
        }
        replaced = {**running, "MainPID": "322"}
        with (
            patch.object(
                watchdog,
                "service_properties",
                side_effect=[running, replaced],
            ),
            patch.object(watchdog, "read_boot_id", return_value=BOOT_ID),
            patch.object(watchdog, "process_start_ticks", return_value=77),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "tunnel_identity_ok", return_value=True),
        ):
            identity, failure = watchdog.tunnel_service_process_identity(
                watchdog.DEFAULT_TUNNEL_SERVICE,
                watchdog.DEFAULT_PROFILE,
                20,
            )
        self.assertIsNone(identity)
        self.assertEqual(
            "tunnel-service-changed-after-dependency-probe",
            failure,
        )

    def test_tunnel_identity_reprobe_rejects_startup_grace(self) -> None:
        running = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "321",
        }
        with (
            patch.object(watchdog, "service_properties", return_value=running),
            patch.object(watchdog, "read_boot_id", return_value=BOOT_ID),
            patch.object(watchdog, "process_start_ticks", return_value=77),
            patch.object(watchdog, "process_age_seconds", return_value=1.0),
            patch.object(watchdog, "tunnel_identity_ok", return_value=True),
        ):
            identity, failure = watchdog.tunnel_service_process_identity(
                watchdog.DEFAULT_TUNNEL_SERVICE,
                watchdog.DEFAULT_PROFILE,
                20,
            )
        self.assertIsNone(identity)
        self.assertEqual(
            "tunnel-service-startup-grace-after-dependency-probe",
            failure,
        )

    def test_metric_parser_ignores_nonfinite_and_other_series(self) -> None:
        metrics = (
            "other_metric 4\n"
            "commands_poll_last_successful_timestamp_seconds NaN\n"
            "commands_poll_last_successful_timestamp_seconds{scope=\"a\"} 42.5 123\n"
        )
        self.assertEqual(
            (42.5,),
            watchdog.prometheus_metric_samples(
                metrics, watchdog.CONTROL_PLANE_POLL_METRIC
            ),
        )

    def test_missing_poll_evidence_is_indeterminate_not_restartable(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "321",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=77),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "tunnel_identity_ok", return_value=True),
            patch.object(watchdog, "get_probe", return_value=True),
            patch.object(
                watchdog,
                "control_plane_poll_probe",
                return_value="control-plane-metrics-unavailable",
            ),
        ):
            result = watchdog.probe_component(
                component="tunnel",
                service="tunnel-client-grabowski.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url=watchdog.DEFAULT_HEALTH_URL,
                ready_url=watchdog.DEFAULT_READY_URL,
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(
            ("control-plane-metrics-unavailable",), result.reasons
        )

    def test_missing_and_invalid_poll_evidence_remain_indeterminate(self) -> None:
        for failure in (
            "control-plane-poll-missing",
            "control-plane-poll-timestamp-invalid",
        ):
            with self.subTest(failure=failure):
                with (
                    patch.object(
                        watchdog,
                        "service_properties",
                        return_value={
                            "LoadState": "loaded",
                            "ActiveState": "active",
                            "SubState": "running",
                            "MainPID": "321",
                        },
                    ),
                    patch.object(watchdog, "process_start_ticks", return_value=77),
                    patch.object(
                        watchdog, "process_age_seconds", return_value=120.0
                    ),
                    patch.object(watchdog, "tunnel_identity_ok", return_value=True),
                    patch.object(watchdog, "get_probe", return_value=True),
                    patch.object(
                        watchdog,
                        "control_plane_poll_probe",
                        return_value=failure,
                    ),
                ):
                    result = watchdog.probe_component(
                        component="tunnel",
                        service="tunnel-client-grabowski.service",
                        runtime_root=Path("/runtime"),
                        module="grabowski_operator",
                        profile="grabowski",
                        host="127.0.0.1",
                        port=18181,
                        health_url=watchdog.DEFAULT_HEALTH_URL,
                        ready_url=watchdog.DEFAULT_READY_URL,
                        startup_grace=20,
                        http_timeout=2,
                    )
                self.assertEqual("indeterminate", result.status)
                self.assertEqual((failure,), result.reasons)

    def test_readiness_failure_with_live_and_fresh_poll_is_indeterminate(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "321",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=77),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "tunnel_identity_ok", return_value=True),
            patch.object(watchdog, "get_probe", side_effect=[True, False]),
            patch.object(watchdog, "control_plane_poll_probe", return_value=None),
        ):
            result = watchdog.probe_component(
                component="tunnel",
                service="tunnel-client-grabowski.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url=watchdog.DEFAULT_HEALTH_URL,
                ready_url=watchdog.DEFAULT_READY_URL,
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(("readiness-failed",), result.reasons)

    def test_missing_readiness_dependency_is_distinct_and_non_restartable(self) -> None:
        result, state = self.classify(
            self.readiness_probe(),
            watchdog.WatchdogState(),
            dependency_failure="mcp-http-request-failed",
        )
        self.assertEqual("dependency-unavailable", result.status)
        self.assertEqual(("readiness-dependency-unavailable",), result.reasons)
        self.assertEqual(321, result.pid)
        self.assertEqual(BOOT_ID, state.readiness_dependency_unavailable_boot_id)
        self.assertEqual(321, state.readiness_dependency_unavailable_pid)
        self.assertEqual(
            77, state.readiness_dependency_unavailable_start_ticks
        )
        self.assertFalse(
            state._readiness_dependency_evidence_loaded_from_disk
        )

    def test_normal_readiness_backpressure_is_not_restartable(self) -> None:
        result, state = self.classify(
            self.readiness_probe(),
            watchdog.WatchdogState(),
            dependency_failure=None,
        )
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(("readiness-failed",), result.reasons)
        self.assertIsNone(state.readiness_dependency_unavailable_pid)

    def test_dependency_recovery_requires_persisted_then_loaded_evidence(self) -> None:
        probe = self.readiness_probe()
        outage, fresh_state = self.classify(
            probe,
            watchdog.WatchdogState(),
            dependency_failure="mcp-http-request-failed",
        )
        self.assertEqual("dependency-unavailable", outage.status)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            watchdog.save_state(path, fresh_state)
            loaded_state = watchdog.load_state(path)
        result, recovered_state = self.classify(
            probe,
            loaded_state,
            dependency_failure=None,
        )
        self.assertEqual("unhealthy", result.status)
        self.assertEqual(
            ("readiness-stale-after-dependency-recovered",),
            result.reasons,
        )
        self.assertTrue(
            recovered_state._readiness_dependency_evidence_loaded_from_disk
        )

    def test_fresh_in_memory_evidence_never_authorizes_recovery(self) -> None:
        with self.assertRaises(TypeError):
            watchdog.WatchdogState(
                _readiness_dependency_evidence_loaded_from_disk=True,
            )
        probe = self.readiness_probe()
        _, state = self.classify(
            probe,
            watchdog.WatchdogState(),
            dependency_failure="mcp-http-request-failed",
        )
        recovered, state = self.classify(
            probe,
            state,
            dependency_failure=None,
        )
        self.assertEqual("indeterminate", recovered.status)
        self.assertEqual(("readiness-failed",), recovered.reasons)
        self.assertFalse(
            state._readiness_dependency_evidence_loaded_from_disk
        )

    def test_reentrant_dependency_probe_does_not_manufacture_disk_evidence(self) -> None:
        probe = self.readiness_probe()
        with (
            patch.object(
                watchdog,
                "mcp_http_probe",
                side_effect=[
                    "mcp-http-request-failed",
                    "mcp-http-request-failed",
                    None,
                ],
            ),
            patch.object(
                watchdog,
                "tunnel_service_process_identity",
                return_value=(self.tunnel_identity(), None),
            ),
        ):
            state = watchdog.WatchdogState()
            results = []
            for _ in range(3):
                result, state = watchdog.classify_tunnel_readiness_dependency(
                    probe,
                    state,
                    service=watchdog.DEFAULT_TUNNEL_SERVICE,
                    profile=watchdog.DEFAULT_PROFILE,
                    startup_grace=20,
                    mcp_url=watchdog.DEFAULT_MCP_URL,
                    timeout=2,
                )
                results.append(result.status)
        self.assertEqual(
            ["dependency-unavailable", "dependency-unavailable", "indeterminate"],
            results,
        )
        self.assertFalse(
            state._readiness_dependency_evidence_loaded_from_disk
        )

    def test_reboot_pid_reuse_invalidates_loaded_dependency_evidence(self) -> None:
        state = watchdog.WatchdogState(
            readiness_dependency_unavailable_boot_id=BOOT_ID,
            readiness_dependency_unavailable_pid=321,
            readiness_dependency_unavailable_start_ticks=77,
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            watchdog.save_state(path, state)
            loaded_state = watchdog.load_state(path)
        new_boot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        result, state = self.classify(
            self.readiness_probe(boot_id=new_boot),
            loaded_state,
            dependency_failure=None,
            identity=self.tunnel_identity(boot_id=new_boot),
        )
        self.assertEqual("indeterminate", result.status)
        self.assertIsNone(state.readiness_dependency_unavailable_boot_id)
        self.assertIsNone(state.readiness_dependency_unavailable_pid)

    def test_process_replacement_during_dependency_probe_fails_safe(self) -> None:
        result, state = self.classify(
            self.readiness_probe(),
            watchdog.WatchdogState(),
            dependency_failure="mcp-http-request-failed",
            identity=self.tunnel_identity(pid=322, start_ticks=91),
        )
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(
            ("tunnel-service-changed-after-dependency-probe",),
            result.reasons,
        )
        self.assertIsNone(state.readiness_dependency_unavailable_pid)

    def test_post_dependency_startup_grace_fails_safe(self) -> None:
        result, state = self.classify(
            self.readiness_probe(),
            watchdog.WatchdogState(),
            dependency_failure=None,
            identity_failure=(
                "tunnel-service-startup-grace-after-dependency-probe"
            ),
        )
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(
            ("tunnel-service-startup-grace-after-dependency-probe",),
            result.reasons,
        )
        self.assertIsNone(state.readiness_dependency_unavailable_pid)

    def test_unprovable_post_dependency_identity_fails_safe(self) -> None:
        result, state = self.classify(
            self.readiness_probe(),
            watchdog.WatchdogState(),
            dependency_failure=None,
            identity_failure=(
                "tunnel-service-identity-unavailable-after-dependency-probe"
            ),
        )
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(
            ("tunnel-service-identity-unavailable-after-dependency-probe",),
            result.reasons,
        )
        self.assertIsNone(state.readiness_dependency_unavailable_pid)

    def test_readiness_failure_with_stale_poll_remains_restartable(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "321",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=77),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "tunnel_identity_ok", return_value=True),
            patch.object(watchdog, "get_probe", side_effect=[True, False]),
            patch.object(
                watchdog,
                "control_plane_poll_probe",
                return_value="control-plane-poll-stale",
            ),
        ):
            result = watchdog.probe_component(
                component="tunnel",
                service="tunnel-client-grabowski.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url=watchdog.DEFAULT_HEALTH_URL,
                ready_url=watchdog.DEFAULT_READY_URL,
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("unhealthy", result.status)
        self.assertEqual(
            ("control-plane-poll-stale", "readiness-failed"), result.reasons
        )

    def test_stale_poll_is_unhealthy_and_enters_restart_path(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "321",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=77),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "tunnel_identity_ok", return_value=True),
            patch.object(watchdog, "get_probe", return_value=True),
            patch.object(
                watchdog,
                "control_plane_poll_probe",
                return_value="control-plane-poll-stale",
            ),
        ):
            result = watchdog.probe_component(
                component="tunnel",
                service="tunnel-client-grabowski.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url=watchdog.DEFAULT_HEALTH_URL,
                ready_url=watchdog.DEFAULT_READY_URL,
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("unhealthy", result.status)
        self.assertEqual(("control-plane-poll-stale",), result.reasons)

        state = watchdog.WatchdogState()
        actions = []
        for now in (1_000, 1_030, 1_060):
            action, state = watchdog.decide(
                state,
                now=now,
                failure_threshold=3,
                max_restarts=3,
                restart_window=900,
                jitter_source=lambda: 0.0,
            )
            actions.append(action)
        self.assertEqual(["observe", "observe", "restart"], actions)
        self.assertEqual(1, state.restart_generation)
        self.assertEqual([1_060], state.restart_timestamps)


class McpHttpLivenessProbeTests(unittest.TestCase):
    def test_live_http_probe_uses_one_session_free_get(self) -> None:
        payload = json.dumps(
            {
                "healthy": True,
                "session_creation_lock_available": True,
            }
        ).encode("utf-8")
        with patch.object(
            watchdog,
            "_mcp_http_request",
            return_value=(
                200,
                {"content-type": "application/json"},
                payload,
            ),
        ) as request:
            self.assertIsNone(
                watchdog.mcp_http_probe(
                    "http://127.0.0.1:18181/_grabowski/mcp-liveness", 2
                )
            )
        request.assert_called_once_with(
            host="127.0.0.1",
            port=18181,
            path="/_grabowski/mcp-liveness",
            timeout=2,
        )

    def test_live_http_failures_are_precise(self) -> None:
        with patch.object(
            watchdog,
            "_mcp_http_request",
            side_effect=watchdog.McpProbeFailure("mcp-http-request-failed"),
        ):
            self.assertEqual(
                "mcp-http-request-failed",
                watchdog.mcp_http_probe(watchdog.DEFAULT_MCP_URL, 2),
            )
        with patch.object(
            watchdog,
            "_mcp_http_request",
            return_value=(503, {"content-type": "application/json"}, b"{}"),
        ):
            self.assertEqual(
                "mcp-session-creation-lock-busy",
                watchdog.mcp_http_probe(watchdog.DEFAULT_MCP_URL, 2),
            )
        with patch.object(
            watchdog,
            "_mcp_http_request",
            return_value=(200, {"content-type": "text/plain"}, b"ok"),
        ):
            self.assertEqual(
                "mcp-http-content-type-invalid",
                watchdog.mcp_http_probe(watchdog.DEFAULT_MCP_URL, 2),
            )
        with patch.object(
            watchdog,
            "_mcp_http_request",
            return_value=(
                200,
                {"content-type": "application/json"},
                b'{"healthy":true,"session_creation_lock_available":false}',
            ),
        ):
            self.assertEqual(
                "mcp-session-creation-lock-busy",
                watchdog.mcp_http_probe(watchdog.DEFAULT_MCP_URL, 2),
            )

    def test_live_endpoint_failure_makes_operator_unhealthy(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "123",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=42),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "operator_identity_ok", return_value=True),
            patch.object(
                watchdog,
                "mcp_http_probe",
                return_value="mcp-session-creation-lock-busy",
            ),
            patch.object(
                watchdog, "mcp_stdio_probe_from_runtime", return_value=None
            ),
        ):
            result = watchdog.probe_component(
                component="operator",
                service="grabowski-operator.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url="http://127.0.0.1:18080/healthz",
                ready_url="http://127.0.0.1:18080/readyz",
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("unhealthy", result.status)
        self.assertEqual(("mcp-session-creation-lock-busy",), result.reasons)

    def test_concrete_failure_outranks_runtime_unhealthy(self) -> None:
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "LoadState": "loaded",
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "123",
                },
            ),
            patch.object(watchdog, "process_start_ticks", return_value=42),
            patch.object(watchdog, "process_age_seconds", return_value=120.0),
            patch.object(watchdog, "operator_identity_ok", return_value=True),
            patch.object(
                watchdog,
                "mcp_http_probe",
                return_value="mcp-runtime-unhealthy",
            ),
            patch.object(
                watchdog,
                "mcp_stdio_probe_from_runtime",
                return_value="mcp-stdio-process-exited",
            ),
        ):
            result = watchdog.probe_component(
                component="operator",
                service="grabowski-operator.service",
                runtime_root=Path("/runtime"),
                module="grabowski_operator",
                profile="grabowski",
                host="127.0.0.1",
                port=18181,
                health_url="http://127.0.0.1:18080/healthz",
                ready_url="http://127.0.0.1:18080/readyz",
                startup_grace=20,
                http_timeout=2,
            )
        self.assertEqual("unhealthy", result.status)
        self.assertEqual(("mcp-runtime-unhealthy",), result.reasons)

    def test_stack_dump_atomic_replace_preserves_hardlink_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            victim = root / "victim.log"
            path = root / "stack.log"
            victim.write_bytes(b"keep-me")
            path.hardlink_to(victim)
            old_inode = path.stat().st_ino
            self.assertTrue(
                watchdog._write_stack_dump_target(path, b"new-dump", 16)
            )
            self.assertEqual(b"keep-me", victim.read_bytes())
            self.assertEqual(b"new-dump", path.read_bytes())
            self.assertNotEqual(old_inode, path.stat().st_ino)
            self.assertEqual(1, path.stat().st_nlink)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_stack_dump_atomic_replace_preserves_symlink_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            victim = root / "victim.log"
            path = root / "stack.log"
            victim.write_bytes(b"keep-me")
            path.symlink_to(victim)
            self.assertTrue(
                watchdog._write_stack_dump_target(path, b"new-dump", 16)
            )
            self.assertEqual(b"keep-me", victim.read_bytes())
            self.assertFalse(path.is_symlink())
            self.assertEqual(b"new-dump", path.read_bytes())

    def test_stack_dump_pending_replace_preserves_link_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            victim = root / "victim.log"
            path = root / "stack.log"
            pending = root / ".stackdump.pending.tmp"
            victim.write_bytes(b"keep-me")
            pending.symlink_to(victim)
            self.assertTrue(
                watchdog._write_stack_dump_target(path, b"new-dump", 16)
            )
            self.assertEqual(b"keep-me", victim.read_bytes())
            self.assertFalse(pending.exists())
            self.assertEqual(b"new-dump", path.read_bytes())

    def test_stack_dump_slot_ring_is_generation_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            first = watchdog._stack_dump_slot_path(state_dir, 1)
            wrapped = watchdog._stack_dump_slot_path(
                state_dir, 1 + watchdog.STACK_DUMP_SLOT_COUNT
            )
            self.assertEqual(first, wrapped)
            self.assertIn(watchdog.STACK_DUMP_DIRECTORY_NAME, first.parts)

    def test_stack_dump_request_extracts_only_new_memfd_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=99),
                patch.object(
                    watchdog,
                    "_process_start_ticks",
                    side_effect=[42, 42, 42],
                ),
                patch.object(watchdog, "_stack_dump_memfd", return_value=7),
                patch.object(
                    watchdog, "_stack_dump_memfd_is_bounded", return_value=True
                ),
                patch.object(
                    watchdog,
                    "_stack_dump_memfd_position",
                    side_effect=[10, 18],
                ) as position,
                patch.object(
                    watchdog,
                    "_read_stack_dump_memfd",
                    return_value=b"new-dump",
                ) as read,
                patch.object(
                    watchdog,
                    "_write_stack_dump_target",
                    return_value=True,
                ) as write,
                patch.object(watchdog.signal, "pidfd_send_signal") as send_signal,
                patch.object(watchdog.os, "close") as close,
                patch.object(watchdog.time, "sleep") as sleep,
            ):
                receipt = watchdog.request_python_stack_dump(
                    123,
                    state_dir=state_dir,
                    restart_generation=9,
                    captured_at_unix=1_000,
                    expected_start_ticks=42,
                    max_bytes=4_096,
                )
            self.assertIsNotNone(receipt)
            assert receipt is not None
            self.assertEqual(9, receipt["restart_generation"])
            self.assertEqual(1, receipt["slot"])
            self.assertEqual(123, receipt["pid"])
            self.assertEqual(42, receipt["process_start_ticks"])
            self.assertEqual(8, receipt["payload_bytes"])
            self.assertEqual(
                "operator-stackdumps-v1/slot-1.dump",
                receipt["relative_path"],
            )
            send_signal.assert_called_once_with(99, watchdog.signal.SIGUSR1)
            close.assert_called_once_with(99)
            sleep.assert_called_once_with(0.25)
            self.assertEqual(2, position.call_count)
            read.assert_called_once_with(
                123, 7, 10, 18, 4_096, Path("/proc")
            )
            written_path, evidence, limit = write.call_args.args
            self.assertEqual(
                watchdog._stack_dump_slot_path(state_dir, 9), written_path
            )
            self.assertEqual(4_096, limit)
            header_bytes, stack = evidence.split(b"\n", 1)
            header = json.loads(header_bytes)
            self.assertEqual(9, header["restart_generation"])
            self.assertEqual(b"new-dump", stack)
            self.assertEqual(
                receipt["evidence_sha256"],
                hashlib.sha256(evidence).hexdigest(),
            )

    def test_failed_publish_leaves_only_self_identifying_old_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_dir = Path(temp_dir)
            slot = watchdog._stack_dump_slot_path(state_dir, 1)
            old = watchdog._stack_dump_evidence_bytes(
                b"old-dump",
                pid=11,
                restart_generation=1,
                captured_at_unix=100,
                process_start_ticks=7,
                max_bytes=4_096,
            )
            assert old is not None
            self.assertTrue(
                watchdog._write_stack_dump_target(slot, old[0], 4_096)
            )
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=99),
                patch.object(
                    watchdog,
                    "_process_start_ticks",
                    side_effect=[42, 42, 42],
                ),
                patch.object(watchdog, "_stack_dump_memfd", return_value=7),
                patch.object(
                    watchdog, "_stack_dump_memfd_is_bounded", return_value=True
                ),
                patch.object(
                    watchdog,
                    "_stack_dump_memfd_position",
                    side_effect=[0, 8],
                ),
                patch.object(
                    watchdog,
                    "_read_stack_dump_memfd",
                    return_value=b"new-dump",
                ),
                patch.object(
                    watchdog,
                    "_write_stack_dump_target",
                    return_value=False,
                ),
                patch.object(watchdog.signal, "pidfd_send_signal"),
                patch.object(watchdog.os, "close"),
                patch.object(watchdog.time, "sleep"),
            ):
                receipt = watchdog.request_python_stack_dump(
                    123,
                    state_dir=state_dir,
                    restart_generation=9,
                    captured_at_unix=1_000,
                    expected_start_ticks=42,
                    max_bytes=4_096,
                )
            self.assertIsNone(receipt)
            header = json.loads(slot.read_bytes().split(b"\n", 1)[0])
            self.assertEqual(1, header["restart_generation"])
            self.assertNotEqual(9, header["restart_generation"])

    def test_stack_dump_request_fails_without_unique_memfd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=99),
                patch.object(watchdog, "_process_start_ticks", return_value=42),
                patch.object(watchdog, "_stack_dump_memfd", return_value=None),
                patch.object(watchdog.os, "close"),
            ):
                self.assertIsNone(
                    watchdog.request_python_stack_dump(
                        123,
                        state_dir=Path(temp_dir),
                        restart_generation=1,
                        captured_at_unix=100,
                        expected_start_ticks=42,
                    )
                )

    def test_stack_dump_request_fails_closed_without_pidfd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=None),
                patch.object(watchdog, "_stack_dump_memfd") as memfd,
            ):
                self.assertIsNone(
                    watchdog.request_python_stack_dump(
                        123,
                        state_dir=Path(temp_dir),
                        restart_generation=1,
                        captured_at_unix=100,
                        expected_start_ticks=42,
                    )
                )
            memfd.assert_not_called()

    def test_stack_dump_request_does_not_signal_unbounded_memfd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=99),
                patch.object(watchdog, "_process_start_ticks", return_value=42),
                patch.object(watchdog, "_stack_dump_memfd", return_value=7),
                patch.object(
                    watchdog, "_stack_dump_memfd_is_bounded", return_value=False
                ),
                patch.object(watchdog.signal, "pidfd_send_signal") as send_signal,
                patch.object(watchdog.os, "close"),
            ):
                self.assertIsNone(
                    watchdog.request_python_stack_dump(
                        123,
                        state_dir=Path(temp_dir),
                        restart_generation=1,
                        captured_at_unix=100,
                        expected_start_ticks=42,
                    )
                )
            send_signal.assert_not_called()

    def test_stack_dump_request_does_not_signal_when_memfd_is_full(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=99),
                patch.object(watchdog, "_process_start_ticks", return_value=42),
                patch.object(watchdog, "_stack_dump_memfd", return_value=7),
                patch.object(
                    watchdog, "_stack_dump_memfd_is_bounded", return_value=True
                ),
                patch.object(
                    watchdog,
                    "_stack_dump_memfd_position",
                    return_value=watchdog.STACK_DUMP_MAX_BYTES,
                ),
                patch.object(watchdog.signal, "pidfd_send_signal") as send_signal,
                patch.object(watchdog.os, "close"),
            ):
                self.assertIsNone(
                    watchdog.request_python_stack_dump(
                        123,
                        state_dir=Path(temp_dir),
                        restart_generation=1,
                        captured_at_unix=100,
                        expected_start_ticks=42,
                    )
                )
            send_signal.assert_not_called()

    def test_stack_dump_request_does_not_signal_after_pid_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.object(watchdog, "_stack_dump_pidfd", return_value=99),
                patch.object(
                    watchdog,
                    "_process_start_ticks",
                    side_effect=[42, 43],
                ),
                patch.object(watchdog, "_stack_dump_memfd", return_value=7),
                patch.object(
                    watchdog, "_stack_dump_memfd_is_bounded", return_value=True
                ),
                patch.object(watchdog, "_stack_dump_memfd_position", return_value=10),
                patch.object(watchdog.signal, "pidfd_send_signal") as send_signal,
                patch.object(watchdog.os, "close"),
            ):
                self.assertIsNone(
                    watchdog.request_python_stack_dump(
                        123,
                        state_dir=Path(temp_dir),
                        restart_generation=1,
                        captured_at_unix=100,
                        expected_start_ticks=42,
                    )
                )
            send_signal.assert_not_called()



class BackoffDecisionTests(unittest.TestCase):
    def decide(self, state, *, now, jitter=0.0, **overrides):
        options = {
            "failure_threshold": 1,
            "max_restarts": 10,
            "restart_window": 900,
            "jitter_source": lambda: jitter,
        }
        options.update(overrides)
        return watchdog.decide(state, now=now, **options)

    def test_restart_threshold_and_budget(self) -> None:
        state = watchdog.WatchdogState()
        action, state = watchdog.decide(state, now=100, failure_threshold=2, max_restarts=1, restart_window=900)
        self.assertEqual("observe", action)
        action, state = watchdog.decide(state, now=101, failure_threshold=2, max_restarts=1, restart_window=900)
        self.assertEqual("restart", action)
        state.consecutive_failures = 1
        action, _ = watchdog.decide(state, now=102, failure_threshold=2, max_restarts=1, restart_window=900)
        self.assertEqual("budget-exhausted", action)

    def test_backoff_doubles_and_defers_restarts(self) -> None:
        action, state = self.decide(watchdog.WatchdogState(), now=1000)
        self.assertEqual("restart", action)
        self.assertEqual(1, state.backoff_level)
        self.assertEqual(1060, state.next_restart_not_before)
        self.assertEqual(1, state.restart_generation)

        action, deferred = self.decide(state, now=1030)
        self.assertEqual("backoff-wait", action)
        self.assertEqual(1060, deferred.next_restart_not_before)
        self.assertEqual(1, deferred.restart_generation)

        action, state = self.decide(deferred, now=1061)
        self.assertEqual("restart", action)
        self.assertEqual(2, state.backoff_level)
        self.assertEqual(1061 + 120, state.next_restart_not_before)
        self.assertEqual(2, state.restart_generation)

    def test_backoff_delay_is_capped(self) -> None:
        state = watchdog.WatchdogState(backoff_level=watchdog.BACKOFF_MAX_LEVEL)
        action, state = self.decide(state, now=5000)
        self.assertEqual("restart", action)
        self.assertEqual(watchdog.BACKOFF_MAX_LEVEL, state.backoff_level)
        self.assertEqual(5000 + watchdog.DEFAULT_BACKOFF_MAX, state.next_restart_not_before)

    def test_backoff_hard_cap_includes_jitter(self) -> None:
        delay = watchdog.backoff_delay_seconds(
            watchdog.BACKOFF_MAX_LEVEL,
            maximum=watchdog.DEFAULT_BACKOFF_MAX,
            jitter=0.999,
        )
        self.assertEqual(watchdog.DEFAULT_BACKOFF_MAX, delay)

    def test_jitter_is_deterministic_and_bounded(self) -> None:
        action, state = self.decide(watchdog.WatchdogState(), now=0, jitter=0.5)
        self.assertEqual("restart", action)
        self.assertEqual(
            int(watchdog.DEFAULT_BACKOFF_BASE * (1 + watchdog.BACKOFF_JITTER_RATIO * 0.5)),
            state.next_restart_not_before,
        )
        with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-jitter"):
            watchdog.backoff_delay_seconds(1, jitter=1.0)
        with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-jitter"):
            watchdog.backoff_delay_seconds(1, jitter=-0.1)
        with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-jitter"):
            watchdog.backoff_delay_seconds(1, jitter=True)
        with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-jitter"):
            watchdog.backoff_delay_seconds(1, jitter="0.5")  # type: ignore[arg-type]

    def test_budget_stays_fail_closed_before_backoff(self) -> None:
        state = watchdog.WatchdogState(restart_timestamps=[990], next_restart_not_before=2000)
        action, _ = self.decide(state, now=1000, max_restarts=1)
        self.assertEqual("budget-exhausted", action)

    def test_healthy_run_resets_backoff_but_keeps_generation(self) -> None:
        state = watchdog.WatchdogState(
            consecutive_failures=2,
            restart_timestamps=[100, 950],
            backoff_level=3,
            next_restart_not_before=1400,
            restart_generation=7,
        )
        reset = watchdog.reset_after_healthy(state, now=1000, restart_window=900)
        self.assertEqual(0, reset.consecutive_failures)
        self.assertEqual(0, reset.backoff_level)
        self.assertEqual(0, reset.next_restart_not_before)
        self.assertEqual([950], reset.restart_timestamps)
        self.assertEqual(7, reset.restart_generation)


class StateFileTests(unittest.TestCase):
    def test_legacy_state_file_reads_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(
                '{"consecutive_failures":2,"restart_timestamps":[5]}',
                encoding="utf-8",
            )
            state = watchdog.load_state(path)
            self.assertEqual(2, state.consecutive_failures)
            self.assertEqual([5], state.restart_timestamps)
            self.assertEqual(0, state.backoff_level)
            self.assertEqual(0, state.next_restart_not_before)
            self.assertEqual(0, state.restart_generation)

    def test_invalid_backoff_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(
                '{"consecutive_failures":0,"restart_timestamps":[],'
                '"backoff_level":"high"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-state-shape"):
                watchdog.load_state(path)

    def test_boolean_numeric_state_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(
                '{"consecutive_failures":true,"restart_timestamps":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(watchdog.WatchdogError, "invalid-state-shape"):
                watchdog.load_state(path)

    def test_state_roundtrip_preserves_backoff_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            original = watchdog.WatchdogState(
                1,
                [10, 20],
                4,
                5000,
                9,
                readiness_dependency_unavailable_boot_id=BOOT_ID,
                readiness_dependency_unavailable_pid=321,
                readiness_dependency_unavailable_start_ticks=77,
            )
            watchdog.save_state(path, original)
            loaded = watchdog.load_state(path)
            self.assertEqual(original, loaded)
            self.assertTrue(
                loaded._readiness_dependency_evidence_loaded_from_disk
            )

    def test_legacy_dependency_identity_is_loaded_but_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(
                '{"consecutive_failures":0,"restart_timestamps":[],'
                '"readiness_dependency_unavailable_pid":321,'
                '"readiness_dependency_unavailable_start_ticks":77}',
                encoding="utf-8",
            )
            loaded = watchdog.load_state(path)
        self.assertIsNone(loaded.readiness_dependency_unavailable_boot_id)
        self.assertIsNone(loaded.readiness_dependency_unavailable_pid)
        self.assertFalse(
            loaded._readiness_dependency_evidence_loaded_from_disk
        )

    def test_malformed_dependency_boot_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(
                '{"consecutive_failures":0,"restart_timestamps":[],'
                '"readiness_dependency_unavailable_boot_id":"not-a-boot-id",'
                '"readiness_dependency_unavailable_pid":321,'
                '"readiness_dependency_unavailable_start_ticks":77}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                watchdog.WatchdogError, "invalid-state-shape"
            ):
                watchdog.load_state(path)

    def test_partial_dependency_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            path.write_text(
                '{"consecutive_failures":0,"restart_timestamps":[],'
                '"readiness_dependency_unavailable_pid":321}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                watchdog.WatchdogError, "invalid-state-shape"
            ):
                watchdog.load_state(path)

    def test_crash_before_atomic_replace_leaves_no_authorizing_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            state = watchdog.WatchdogState(
                readiness_dependency_unavailable_boot_id=BOOT_ID,
                readiness_dependency_unavailable_pid=321,
                readiness_dependency_unavailable_start_ticks=77,
            )
            with (
                patch.object(
                    watchdog.os,
                    "replace",
                    side_effect=RuntimeError("simulated crash before replace"),
                ),
                self.assertRaisesRegex(RuntimeError, "simulated crash"),
            ):
                watchdog.save_state(path, state)
            self.assertFalse(path.exists())
            self.assertEqual(watchdog.WatchdogState(), watchdog.load_state(path))


class ConnectorSnapshotRefreshTests(unittest.TestCase):
    def _runtime(self, root: Path) -> Path:
        runtime = root / "runtime"
        executable = runtime / ".venv" / "bin" / "python"
        executable.parent.mkdir(parents=True)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        return runtime

    def test_refresh_invokes_runtime_snapshot_module_with_process_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._runtime(Path(tmp))
            completed = watchdog.subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    '{"state":"renewed","reason":"renewal-window",'
                    '"tool_count":155,"session_id_sha256":"' + "a" * 64 + '"}\n'
                ),
                stderr="",
            )
            with patch.object(watchdog.subprocess, "run", return_value=completed) as runner:
                result = watchdog.refresh_connector_snapshot_from_runtime(
                    runtime_root=runtime,
                    host="127.0.0.1",
                    port=18181,
                    connector_pid=123,
                    connector_start_ticks=456,
                )
            self.assertEqual(result["state"], "renewed")
            command = runner.call_args.args[0]
            self.assertIn("grabowski_client_snapshot", command)
            self.assertIn("123", command)
            self.assertIn("456", command)
            self.assertIn("http://127.0.0.1:18181/mcp", command)
            self.assertIn("20.0", command)
            self.assertEqual(runner.call_args.kwargs["timeout"], 22.0)

    def test_runtime_deployment_identity_ignores_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp)
            (runtime / "deployment-manifest.json").write_bytes(b"\xff\xfe")
            self.assertEqual({}, watchdog.runtime_deployment_identity(runtime))

    def test_refresh_failure_is_reported_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._runtime(Path(tmp))
            completed = watchdog.subprocess.CompletedProcess(
                [], 2, stdout='{"state":"error","reason":"bind-failed"}\n', stderr=""
            )
            with patch.object(watchdog.subprocess, "run", return_value=completed):
                result = watchdog.refresh_connector_snapshot_from_runtime(
                    runtime_root=runtime,
                    host="127.0.0.1",
                    port=18181,
                    connector_pid=123,
                    connector_start_ticks=456,
                )
            self.assertEqual(result, {"state": "error", "reason": "bind-failed"})

    def test_healthy_tunnel_runs_refresh_but_check_only_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    ["--component", "tunnel", "--state-dir", tmp]
                )
            )
            probe = watchdog.ProbeResult("healthy", pid=123, age_seconds=30.0, start_ticks=456)
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(watchdog, "refresh_connector_snapshot_from_runtime", return_value={"state": "not_due"}) as refresh,
                patch.object(watchdog, "emit"),
            ):
                self.assertEqual(watchdog.run_watchdog(args), 0)
                refresh.assert_called_once()

            check_args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    ["--component", "tunnel", "--state-dir", tmp, "--check-only"]
                )
            )
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(watchdog, "refresh_connector_snapshot_from_runtime") as refresh,
                patch.object(watchdog, "emit"),
            ):
                self.assertEqual(watchdog.run_watchdog(check_args), 0)
                refresh.assert_not_called()

    def test_healthy_tunnel_is_recovering_until_connector_snapshot_converges(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    ["--component", "tunnel", "--state-dir", tmp]
                )
            )
            probe = watchdog.ProbeResult(
                "healthy", pid=123, age_seconds=30.0, start_ticks=456
            )
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(
                    watchdog,
                    "refresh_connector_snapshot_from_runtime",
                    return_value={"state": "error", "reason": "discover-failed"},
                ),
                patch.object(watchdog, "restart_service") as restart,
                patch.object(watchdog, "emit") as emit,
            ):
                self.assertEqual(1, watchdog.run_watchdog(args))

            restart.assert_not_called()
            state = watchdog.load_state(Path(tmp) / "tunnel-watchdog-state.json")
            self.assertEqual("connector-convergence", state.recovery_phase)
            self.assertFalse(state.recovery_episode_restart_attempted)
            self.assertGreater(state.recovery_episode_started_at_unix, 0)
            self.assertEqual(
                "grabowski.component_watchdog.recovering",
                emit.call_args.args[0],
            )
            self.assertEqual(
                "discover-failed", emit.call_args.kwargs["convergence_reason"]
            )



class WatchdogAdmissionRecoveryTests(unittest.TestCase):
    def _manifest_root(self, root: Path) -> Path:
        runtime = root / "runtime"
        runtime.mkdir()
        (runtime / watchdog.WATCHDOG_RUNTIME_MANIFEST_NAME).write_text(
            json.dumps(
                {
                    "repo_head": "a" * 40,
                    "source_sha256": "b" * 64,
                }
            ),
            encoding="utf-8",
        )
        return runtime

    def test_watchdog_admission_marker_roundtrip_is_private_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state = root / "state"
            state.mkdir(mode=0o700)
            runtime = self._manifest_root(root)
            with patch.object(watchdog.time, "time", return_value=100):
                marker = watchdog.engage_watchdog_admission(
                    state_dir=state,
                    runtime_root=runtime,
                    lifetime_seconds=180,
                )
            path = state / watchdog.WATCHDOG_ADMISSION_MARKER_NAME
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            self.assertEqual("a" * 40, marker["expected_head"])
            self.assertEqual("b" * 64, marker["source_identity_sha256"])
            watchdog.release_watchdog_admission(state_dir=state, marker=marker)
            self.assertFalse(path.exists())

    def test_admission_wait_requires_stable_zero_active_calls(self) -> None:
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
        }
        observations = [
            {
                "valid": True,
                "active": True,
                "state": "active",
                "admission_gate_installed": True,
                **marker,
                "active_tool_calls": 1,
            },
            {
                "valid": True,
                "active": True,
                "state": "active",
                "admission_gate_installed": True,
                **marker,
                "active_tool_calls": 0,
            },
            {
                "valid": True,
                "active": True,
                "state": "active",
                "admission_gate_installed": True,
                **marker,
                "active_tool_calls": 0,
            },
        ]
        with (
            patch.object(
                watchdog,
                "operator_admission_observation",
                side_effect=observations,
            ),
            patch.object(watchdog.time, "sleep"),
            patch.object(
                watchdog.time,
                "monotonic",
                side_effect=itertools.count(),
            ),
        ):
            result = watchdog.wait_for_watchdog_admission_idle(
                marker, host="127.0.0.1", port=18181, timeout=10
            )
        self.assertEqual(3, result["attempts"])
        self.assertEqual(2, result["consecutive_idle_samples"])

    def test_tunnel_drain_requires_balanced_stable_final_responses(self) -> None:
        metrics = "\n".join(
            [
                "commands_queue_length 0",
                "commands_polled_total 10",
                "commands_enqueued_total 10",
                "process_start_time_seconds 5",
                'command_end_to_end_latency_milliseconds_count{latency_type="enqueue_to_response",request_method="initialize"} 4',
                'command_end_to_end_latency_milliseconds_count{latency_type="enqueue_to_response",request_method="tools/call"} 6',
            ]
        )
        with (
            patch.object(watchdog, "get_bounded_text", return_value=metrics),
            patch.object(watchdog.time, "sleep"),
            patch.object(
                watchdog.time,
                "monotonic",
                side_effect=itertools.count(),
            ),
        ):
            result = watchdog.wait_for_watchdog_tunnel_idle(
                metrics_url="http://127.0.0.1:18080/metrics", timeout=10
            )
        self.assertEqual(3, result["attempts"])
        self.assertEqual(
            10.0, result["metrics"]["commands_final_responses_total"]
        )

    def test_tunnel_metrics_treat_missing_final_series_as_idle_zero(self) -> None:
        """Cold exporters may omit histogram series until the first sample."""
        metrics = "\n".join(
            [
                "commands_queue_length 0",
                "commands_polled_total 0",
                "commands_enqueued_total 0",
                "process_start_time_seconds 12",
            ]
        )
        parsed = watchdog.admission_recovery.parse_tunnel_metrics(metrics)
        self.assertEqual(0.0, parsed["commands_final_responses_total"])
        self.assertEqual(0.0, parsed["commands_queue_length"])
        self.assertEqual(0.0, parsed["commands_polled_total"])
        self.assertEqual(0.0, parsed["commands_enqueued_total"])

        with (
            patch.object(watchdog, "get_bounded_text", return_value=metrics),
            patch.object(watchdog.time, "sleep"),
            patch.object(
                watchdog.time,
                "monotonic",
                side_effect=itertools.count(),
            ),
        ):
            result = watchdog.wait_for_watchdog_tunnel_idle(
                metrics_url="http://127.0.0.1:18080/metrics", timeout=10
            )
        self.assertEqual(3, result["attempts"])
        self.assertEqual(
            0.0, result["metrics"]["commands_final_responses_total"]
        )

    def test_tunnel_metrics_still_require_core_counters(self) -> None:
        with self.assertRaisesRegex(
            watchdog.WatchdogError, "watchdog-tunnel-metrics-incomplete"
        ):
            watchdog.admission_recovery.parse_tunnel_metrics(
                "\n".join(
                    [
                        "commands_queue_length 0",
                        "commands_polled_total 0",
                        # missing commands_enqueued_total
                        "process_start_time_seconds 1",
                    ]
                )
            )

    def test_transient_liveness_recovers_after_drain_without_restart(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                ["--component", "operator", "--restart-drain-timeout", "5"]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
        }
        with (
            patch.object(
                watchdog, "engage_watchdog_admission", return_value=marker
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_admission_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_tunnel_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "_operator_recovered_without_replacement",
                return_value=watchdog.ProbeResult(
                    "healthy", pid=123, age_seconds=61, start_ticks=10
                ),
            ),
            patch.object(watchdog, "release_watchdog_admission") as release,
            patch.object(watchdog, "service_action") as service_action,
            patch.object(watchdog, "restart_service") as restart,
        ):
            outcome, probe, _proof = watchdog.safe_operator_restart(
                args,
                watchdog.ProbeResult(
                    "unhealthy", ("mcp-http-request-failed",), 123, 60, 10
                ),
            )
        self.assertEqual("recovered-without-restart", outcome)
        self.assertEqual(
            watchdog.ProbeResult(
                "healthy", pid=123, age_seconds=61, start_ticks=10
            ),
            probe,
        )
        release.assert_called_once()
        service_action.assert_not_called()
        restart.assert_not_called()

    def test_identity_mismatch_remains_restartable_after_http_recovers(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                [
                    "--component",
                    "operator",
                    "--restart-drain-timeout",
                    "5",
                    "--recovery-timeout",
                    "5",
                ]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
        }
        replacement = watchdog.ProbeResult(
            "healthy", pid=456, age_seconds=1, start_ticks=20
        )
        observation = {
            "valid": True,
            "active": True,
            "state": "active",
            "admission_gate_installed": True,
            **marker,
            "active_tool_calls": 0,
        }
        actions: list[tuple[str, str]] = []
        with (
            patch.object(
                watchdog, "engage_watchdog_admission", return_value=marker
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_admission_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_tunnel_idle",
                return_value={"bounded": True},
            ) as tunnel_drain,
            patch.object(
                watchdog,
                "_operator_recovered_without_replacement",
                return_value=watchdog.ProbeResult(
                    "unhealthy", ("operator-identity-mismatch",), 123, 61, 10
                ),
            ),
            patch.object(
                watchdog,
                "service_action",
                side_effect=lambda service, action, **_kwargs: actions.append(
                    (service, action)
                ),
            ),
            patch.object(
                watchdog,
                "restart_service",
                side_effect=lambda service: actions.append((service, "restart")),
            ),
            patch.object(
                watchdog, "_operator_process_is_live", return_value=replacement
            ),
            patch.object(
                watchdog,
                "operator_admission_observation",
                return_value=observation,
            ),
            patch.object(watchdog, "get_probe", return_value=True),
            patch.object(watchdog, "release_watchdog_admission") as release,
            patch.object(watchdog.time, "sleep"),
            patch.object(
                watchdog.time,
                "monotonic",
                side_effect=itertools.count(),
            ),
        ):
            outcome, probe, _proof = watchdog.safe_operator_restart(
                args,
                watchdog.ProbeResult(
                    "unhealthy", ("operator-identity-mismatch",), 123, 60, 10
                ),
            )
        self.assertEqual("restarted", outcome)
        self.assertEqual(replacement, probe)
        self.assertEqual(
            [
                (watchdog.DEFAULT_TUNNEL_SERVICE, "stop"),
                (watchdog.DEFAULT_OPERATOR_SERVICE, "restart"),
                (watchdog.DEFAULT_TUNNEL_SERVICE, "start"),
            ],
            actions,
        )
        release.assert_called_once()
        self.assertEqual(2, tunnel_drain.call_count)

    def test_final_tunnel_drain_failure_prevents_service_mutation(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                ["--component", "operator", "--restart-drain-timeout", "5"]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
        }
        with (
            patch.object(
                watchdog, "engage_watchdog_admission", return_value=marker
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_admission_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_tunnel_idle",
                side_effect=[
                    {"bounded": True},
                    watchdog.WatchdogError("watchdog-tunnel-drain-timeout"),
                ],
            ),
            patch.object(
                watchdog,
                "_operator_recovered_without_replacement",
                return_value=watchdog.ProbeResult(
                    "unhealthy", ("operator-identity-mismatch",), 123, 61, 10
                ),
            ),
            patch.object(watchdog, "release_watchdog_admission") as release,
            patch.object(watchdog, "service_action") as service_action,
            patch.object(watchdog, "restart_service") as restart,
        ):
            with self.assertRaisesRegex(
                watchdog.WatchdogError, "watchdog-tunnel-drain-timeout"
            ):
                watchdog.safe_operator_restart(
                    args,
                    watchdog.ProbeResult(
                        "unhealthy",
                        ("mcp-http-request-failed",),
                        123,
                        60,
                        10,
                    ),
                )
        release.assert_called_once()
        service_action.assert_not_called()
        restart.assert_not_called()

    def test_recovery_timeout_policy_is_bounded_by_service_budget(self) -> None:
        with self.assertRaisesRegex(
            watchdog.WatchdogError, "invalid-recovery-time-policy"
        ):
            watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--restart-drain-timeout",
                        "61",
                    ]
                )
            )
        with self.assertRaisesRegex(
            watchdog.WatchdogError, "invalid-recovery-time-policy"
        ):
            watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--recovery-timeout",
                        "121",
                    ]
                )
            )

    def test_marker_symlink_hardlink_and_owner_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            victim = root / "victim"
            victim.write_text("{}", encoding="utf-8")
            victim.chmod(0o600)
            marker_path = root / watchdog.WATCHDOG_ADMISSION_MARKER_NAME
            marker_path.symlink_to(victim)
            with self.assertRaises(watchdog.WatchdogError):
                watchdog.read_watchdog_admission_marker(marker_path)
            marker_path.unlink()
            marker_path.hardlink_to(victim)
            with self.assertRaisesRegex(
                watchdog.WatchdogError, "watchdog-admission-marker-unsafe"
            ):
                watchdog.read_watchdog_admission_marker(marker_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state = root / "state"
            state.mkdir(mode=0o700)
            runtime = self._manifest_root(root)
            marker = watchdog.engage_watchdog_admission(
                state_dir=state,
                runtime_root=runtime,
                lifetime_seconds=180,
            )
            drifted = dict(marker)
            drifted["token"] = "f" * 64
            with self.assertRaisesRegex(
                watchdog.WatchdogError,
                "watchdog-admission-marker-owner-drift",
            ):
                watchdog.release_watchdog_admission(
                    state_dir=state, marker=drifted
                )
            self.assertTrue(
                (state / watchdog.WATCHDOG_ADMISSION_MARKER_NAME).exists()
            )
            watchdog.release_watchdog_admission(
                state_dir=state, marker=marker
            )

    def test_tunnel_watchdog_defers_for_active_or_expired_recovery_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    ["--component", "tunnel", "--state-dir", temp_dir]
                )
            )
            for expires, expected_state in (
                (1200, "active"),
                (999, "expired-unreconciled"),
            ):
                marker = {
                    "schema_version": 1,
                    "kind": "grabowski_deployment_admission_drain",
                    "token": "a" * 64,
                    "expected_head": "b" * 40,
                    "source_identity_sha256": "c" * 64,
                    "created_at_unix": 900,
                    "expires_at_unix": expires,
                }
                with (
                    self.subTest(marker_state=expected_state),
                    patch.object(
                        watchdog,
                        "read_watchdog_admission_marker",
                        return_value=marker,
                    ),
                    patch.object(watchdog, "probe_component") as probe,
                    patch.object(watchdog, "restart_service") as restart,
                    patch.object(watchdog, "emit") as emit,
                    patch.object(watchdog.time, "time", return_value=1000),
                ):
                    self.assertEqual(1, watchdog.run_watchdog(args))
                probe.assert_not_called()
                restart.assert_not_called()
                self.assertEqual(
                    "grabowski.component_watchdog.recovery_admission_present",
                    emit.call_args.args[0],
                )
                self.assertEqual(
                    expected_state, emit.call_args.kwargs["marker_state"]
                )

    def test_failed_forward_recovery_restores_service_pair_and_re_raises(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                [
                    "--component",
                    "operator",
                    "--restart-drain-timeout",
                    "5",
                    "--recovery-timeout",
                    "5",
                ]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
            "expires_at_unix": 2000,
        }
        with (
            patch.object(
                watchdog, "engage_watchdog_admission", return_value=marker
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_admission_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_tunnel_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "_operator_recovered_without_replacement",
                return_value=watchdog.ProbeResult(
                    "unhealthy", ("operator-identity-mismatch",), 123, 61, 10
                ),
            ),
            patch.object(watchdog, "service_action"),
            patch.object(
                watchdog,
                "restart_service",
                side_effect=watchdog.WatchdogError(
                    "service-restart-request-failed"
                ),
            ),
            patch.object(
                watchdog,
                "_restore_service_pair_after_failed_recovery",
                return_value={"tunnel_restarted": True},
            ) as rollback,
            patch.object(watchdog, "emit") as emit,
        ):
            with self.assertRaisesRegex(
                watchdog.WatchdogError,
                "service-restart-request-failed",
            ):
                watchdog.safe_operator_restart(
                    args,
                    watchdog.ProbeResult(
                        "unhealthy",
                        ("mcp-http-request-failed",),
                        123,
                        60,
                        10,
                    ),
                )
        rollback.assert_called_once_with(args, marker)
        self.assertEqual(
            "grabowski.component_watchdog.rollback_recovered",
            emit.call_args.args[0],
        )

    def test_failed_rollback_keeps_admission_fail_closed(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                ["--component", "operator", "--restart-drain-timeout", "5"]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
            "expires_at_unix": 2000,
        }
        with (
            patch.object(
                watchdog, "engage_watchdog_admission", return_value=marker
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_admission_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_tunnel_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "_operator_recovered_without_replacement",
                return_value=watchdog.ProbeResult(
                    "unhealthy", ("operator-identity-mismatch",), 123, 61, 10
                ),
            ),
            patch.object(watchdog, "service_action"),
            patch.object(
                watchdog,
                "restart_service",
                side_effect=watchdog.WatchdogError(
                    "service-restart-request-failed"
                ),
            ),
            patch.object(
                watchdog,
                "_restore_service_pair_after_failed_recovery",
                return_value=None,
            ),
            patch.object(
                watchdog, "release_watchdog_admission"
            ) as release,
            patch.object(watchdog, "emit") as emit,
        ):
            with self.assertRaises(watchdog.WatchdogError):
                watchdog.safe_operator_restart(
                    args,
                    watchdog.ProbeResult(
                        "unhealthy",
                        ("mcp-http-request-failed",),
                        123,
                        60,
                        10,
                    ),
                )
        release.assert_not_called()
        self.assertEqual(
            "grabowski.component_watchdog.rollback_fail_closed",
            emit.call_args.args[0],
        )

    def test_rollback_helper_requires_marker_bound_operator_before_tunnel(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                ["--component", "operator", "--recovery-timeout", "5"]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
        }
        replacement = watchdog.ProbeResult(
            "healthy", pid=456, age_seconds=1, start_ticks=20
        )
        observation = {
            "valid": True,
            "active": True,
            "state": "active",
            "admission_gate_installed": True,
            **marker,
            "active_tool_calls": 0,
        }
        with (
            patch.object(
                watchdog, "_operator_process_is_live", return_value=replacement
            ) as operator_probe,
            patch.object(
                watchdog,
                "operator_admission_observation",
                return_value=observation,
            ),
            patch.object(watchdog, "service_action") as service_action,
            patch.object(watchdog, "get_probe", return_value=True),
            patch.object(watchdog, "release_watchdog_admission") as release,
            patch.object(watchdog.time, "sleep"),
            patch.object(
                watchdog.time,
                "monotonic",
                side_effect=itertools.count(),
            ),
        ):
            result = watchdog._restore_service_pair_after_failed_recovery(
                args, marker
            )
        self.assertEqual(
            {
                "operator_pid": 456,
                "operator_start_ticks": 20,
                "tunnel_restarted": True,
            },
            result,
        )
        self.assertIsNone(operator_probe.call_args.args[0])
        self.assertEqual(
            [
                ((watchdog.DEFAULT_OPERATOR_SERVICE, "start"),),
                ((watchdog.DEFAULT_TUNNEL_SERVICE, "start"),),
            ],
            service_action.call_args_list,
        )
        release.assert_called_once_with(state_dir=args.state_dir, marker=marker)

    def test_ambiguous_tunnel_stop_enters_rollback_handling(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(
                ["--component", "operator", "--restart-drain-timeout", "5"]
            )
        )
        marker = {
            "token": "a" * 64,
            "expected_head": "b" * 40,
            "source_identity_sha256": "c" * 64,
            "expires_at_unix": 2000,
        }
        with (
            patch.object(
                watchdog, "engage_watchdog_admission", return_value=marker
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_admission_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "wait_for_watchdog_tunnel_idle",
                return_value={"bounded": True},
            ),
            patch.object(
                watchdog,
                "_operator_recovered_without_replacement",
                return_value=watchdog.ProbeResult(
                    "unhealthy", ("operator-identity-mismatch",), 123, 61, 10
                ),
            ),
            patch.object(
                watchdog,
                "service_action",
                side_effect=watchdog.WatchdogError("service-stop-timeout"),
            ),
            patch.object(watchdog, "restart_service") as restart,
            patch.object(
                watchdog,
                "_restore_service_pair_after_failed_recovery",
                return_value={"tunnel_restarted": True},
            ) as rollback,
            patch.object(
                watchdog, "release_watchdog_admission"
            ) as release,
            patch.object(watchdog, "emit"),
        ):
            with self.assertRaises(watchdog.RecoveryMutationError) as raised:
                watchdog.safe_operator_restart(
                    args,
                    watchdog.ProbeResult(
                        "unhealthy",
                        ("mcp-http-request-failed",),
                        123,
                        60,
                        10,
                    ),
                )
        self.assertTrue(raised.exception.rollback_recovered)
        rollback.assert_called_once_with(args, marker)
        restart.assert_not_called()
        release.assert_not_called()

    def test_run_watchdog_marks_failed_rollback_as_unit_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--state-dir",
                        temp_dir,
                        "--failure-threshold",
                        "1",
                        "--startup-grace",
                        "0",
                    ]
                )
            )
            probe = watchdog.ProbeResult(
                "unhealthy", ("mcp-http-request-failed",), 123, 60, 10
            )
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(
                    watchdog,
                    "safe_operator_restart",
                    side_effect=watchdog.RecoveryMutationError(
                        "operator-safe-recovery-timeout",
                        rollback_recovered=False,
                    ),
                ),
                patch.object(watchdog, "request_python_stack_dump"),
                patch.object(watchdog, "emit") as emit,
                patch.object(watchdog.time, "time", return_value=1000),
            ):
                self.assertEqual(4, watchdog.run_watchdog(args))
        self.assertEqual(
            "grabowski.component_watchdog.restart_fail_closed",
            emit.call_args.args[0],
        )
        self.assertTrue(emit.call_args.kwargs["marker_present"])

    def test_run_watchdog_defers_after_successful_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--state-dir",
                        temp_dir,
                        "--failure-threshold",
                        "1",
                        "--startup-grace",
                        "0",
                    ]
                )
            )
            probe = watchdog.ProbeResult(
                "unhealthy", ("mcp-http-request-failed",), 123, 60, 10
            )
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(
                    watchdog,
                    "safe_operator_restart",
                    side_effect=watchdog.RecoveryMutationError(
                        "service-restart-request-failed",
                        rollback_recovered=True,
                    ),
                ),
                patch.object(watchdog, "request_python_stack_dump"),
                patch.object(watchdog, "emit") as emit,
                patch.object(watchdog.time, "time", return_value=1000),
            ):
                self.assertEqual(1, watchdog.run_watchdog(args))
        self.assertEqual(
            "grabowski.component_watchdog.restart_rolled_back",
            emit.call_args.args[0],
        )

    def test_shared_recovery_lock_serializes_both_component_watchdogs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    ["--component", "tunnel", "--state-dir", temp_dir]
                )
            )
            with (
                watchdog.exclusive_lock(root / "component-recovery.lock"),
                patch.object(watchdog, "probe_component") as probe,
            ):
                with self.assertRaises(watchdog.LockBusy):
                    watchdog.run_watchdog(args)
            probe.assert_not_called()

    def test_run_watchdog_defers_when_safe_drain_cannot_be_proven(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--state-dir",
                        temp_dir,
                        "--failure-threshold",
                        "1",
                        "--startup-grace",
                        "0",
                    ]
                )
            )
            probe = watchdog.ProbeResult(
                "unhealthy", ("mcp-http-request-failed",), 123, 60, 10
            )
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(
                    watchdog,
                    "safe_operator_restart",
                    side_effect=watchdog.WatchdogError(
                        "watchdog-admission-active-calls-timeout"
                    ),
                ),
                patch.object(watchdog, "request_python_stack_dump"),
                patch.object(watchdog, "restart_service") as restart,
                patch.object(watchdog, "emit") as emit,
                patch.object(watchdog.time, "time", return_value=1000),
            ):
                self.assertEqual(1, watchdog.run_watchdog(args))
        restart.assert_not_called()
        self.assertEqual(
            "grabowski.component_watchdog.restart_safety_deferred",
            emit.call_args.args[0],
        )



class WatchdogPolicyTests(unittest.TestCase):
    def test_services_are_independent(self) -> None:
        operator = watchdog.normalize_args(watchdog.parser().parse_args(["--component", "operator"]))
        tunnel = watchdog.normalize_args(watchdog.parser().parse_args(["--component", "tunnel"]))
        self.assertEqual("grabowski-operator.service", operator.service)
        self.assertEqual("tunnel-client-grabowski.service", tunnel.service)

    def test_backoff_policy_defaults_are_bounded(self) -> None:
        args = watchdog.normalize_args(watchdog.parser().parse_args(["--component", "operator"]))
        self.assertEqual(watchdog.DEFAULT_BACKOFF_BASE, args.backoff_base)
        self.assertEqual(watchdog.DEFAULT_BACKOFF_MAX, args.backoff_max)
        self.assertGreaterEqual(args.backoff_max, args.backoff_base)

    def test_dependency_outage_has_structured_nonfailure_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    ["--component", "tunnel", "--state-dir", tmp]
                )
            )
            probe = watchdog.ProbeResult(
                "indeterminate",
                ("readiness-failed",),
                pid=321,
                age_seconds=120.0,
                start_ticks=77,
                boot_id=BOOT_ID,
            )
            with (
                patch.object(watchdog, "probe_component", return_value=probe),
                patch.object(
                    watchdog,
                    "mcp_http_probe",
                    return_value="mcp-http-request-failed",
                ),
                patch.object(
                    watchdog,
                    "tunnel_service_process_identity",
                    return_value=(
                        watchdog.TunnelProcessIdentity(
                            BOOT_ID, 321, 77, 120.0
                        ),
                        None,
                    ),
                ),
                patch.object(watchdog, "restart_service") as restart,
                patch.object(watchdog, "emit") as emit,
            ):
                result = watchdog.run_watchdog(args)

        self.assertEqual(watchdog.DEPENDENCY_UNAVAILABLE_EXIT, result)
        restart.assert_not_called()
        self.assertEqual(
            "grabowski.component_watchdog.dependency_unavailable",
            emit.call_args.args[0],
        )

    def test_restart_service_queues_nonblocking_restart(self) -> None:
        with patch.object(watchdog.subprocess, "run") as run:
            watchdog.restart_service("grabowski-operator.service")

        run.assert_called_once_with(
            [
                "systemctl",
                "--user",
                "--no-block",
                "restart",
                "grabowski-operator.service",
            ],
            check=True,
            stdout=watchdog.subprocess.PIPE,
            stderr=watchdog.subprocess.PIPE,
            text=True,
            timeout=watchdog.SERVICE_RESTART_REQUEST_TIMEOUT_SECONDS,
        )

    def test_restart_service_reports_queue_timeout_separately(self) -> None:
        with patch.object(
            watchdog.subprocess,
            "run",
            side_effect=watchdog.subprocess.TimeoutExpired(
                cmd=["systemctl", "--user", "--no-block", "restart"],
                timeout=watchdog.SERVICE_RESTART_REQUEST_TIMEOUT_SECONDS,
            ),
        ):
            with self.assertRaisesRegex(watchdog.WatchdogError, "service-restart-timeout"):
                watchdog.restart_service("grabowski-operator.service")

    def test_restart_service_preserves_bounded_single_line_systemd_error(self) -> None:
        stderr = "D-Bus request failed\n" + ("x" * 600)
        with patch.object(
            watchdog.subprocess,
            "run",
            side_effect=watchdog.subprocess.CalledProcessError(
                returncode=5,
                cmd=["systemctl", "--user", "--no-block", "restart"],
                stderr=stderr,
            ),
        ):
            with self.assertRaises(watchdog.WatchdogError) as raised:
                watchdog.restart_service("grabowski-operator.service")

        message = str(raised.exception)
        self.assertTrue(message.startswith("service-restart-failed: D-Bus request failed "))
        detail = message.removeprefix("service-restart-failed: ")
        self.assertLessEqual(len(detail), watchdog.SERVICE_RESTART_ERROR_MAX_CHARS)
        self.assertNotIn("\n", detail)

    def test_new_process_instance_detection_is_fail_closed_when_identity_is_uncertain(self) -> None:
        cases = (
            (watchdog.ProbeResult("unhealthy"), watchdog.ProbeResult("healthy"), False),
            (watchdog.ProbeResult("unhealthy"), watchdog.ProbeResult("healthy", pid=456), True),
            (
                watchdog.ProbeResult("unhealthy", pid=123, start_ticks=10),
                watchdog.ProbeResult("healthy", pid=456, start_ticks=10),
                True,
            ),
            (
                watchdog.ProbeResult("unhealthy", pid=123, start_ticks=10),
                watchdog.ProbeResult("healthy", pid=123, start_ticks=20),
                True,
            ),
            (
                watchdog.ProbeResult("unhealthy", pid=123, start_ticks=10),
                watchdog.ProbeResult("healthy", pid=123, start_ticks=10),
                False,
            ),
            (
                watchdog.ProbeResult("unhealthy", pid=123),
                watchdog.ProbeResult("healthy", pid=123, start_ticks=20),
                False,
            ),
        )
        for previous, current, expected in cases:
            with self.subTest(previous=previous, current=current):
                self.assertEqual(
                    expected, watchdog._is_new_process_instance(previous, current)
                )

    def test_default_recovery_timeout_covers_slow_systemd_restart(self) -> None:
        args = watchdog.normalize_args(
            watchdog.parser().parse_args(["--component", "operator"])
        )
        self.assertEqual(watchdog.DEFAULT_RECOVERY_TIMEOUT_SECONDS, args.recovery_timeout)
        self.assertEqual(60.0, args.recovery_timeout)

    def test_recovery_only_after_new_process_is_seen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--state-dir",
                        tmp,
                        "--failure-threshold",
                        "1",
                        "--startup-grace",
                        "0",
                        "--recovery-timeout",
                        "5",
                    ]
                )
            )
            probes = [
                watchdog.ProbeResult(
                    "unhealthy", ("test-failure",), 123, 100.0, start_ticks=10
                ),
                watchdog.ProbeResult("healthy", pid=456, age_seconds=1.0, start_ticks=20),
            ]
            with (
                patch.object(watchdog, "probe_component", side_effect=probes) as probe_component,
                patch.object(
                    watchdog,
                    "safe_operator_restart",
                    return_value=(
                        "restarted",
                        watchdog.ProbeResult(
                            "healthy", pid=456, age_seconds=1.0, start_ticks=20
                        ),
                        {"bounded": True},
                    ),
                ),
                patch.object(watchdog, "restart_service"),
                patch.object(watchdog, "emit"),
                patch.object(watchdog.time, "sleep"),
                patch.object(
                    watchdog.time,
                    "monotonic",
                    side_effect=itertools.chain([0.0, 0.0], itertools.repeat(1.0)),
                ),
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.chain([1000.0], itertools.repeat(1001.0)),
                ),
            ):
                self.assertEqual(0, watchdog.run_watchdog(args))

            self.assertEqual(2, probe_component.call_count)
            state = watchdog.load_state(Path(tmp) / "operator-watchdog-state.json")
            self.assertEqual(0, state.consecutive_failures)
            self.assertEqual(0, state.backoff_level)
            self.assertEqual(0, state.next_restart_not_before)
            self.assertEqual(1, state.restart_generation)
            self.assertEqual([1000], state.restart_timestamps)

    def test_successful_recovery_resets_backoff_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "operator",
                        "--state-dir",
                        tmp,
                        "--failure-threshold",
                        "1",
                        "--startup-grace",
                        "0",
                    ]
                )
            )
            probes = [
                watchdog.ProbeResult("unhealthy", ("test-failure",), 123, 100.0),
                watchdog.ProbeResult("healthy", pid=456, age_seconds=1.0),
            ]
            with (
                patch.object(watchdog, "probe_component", side_effect=probes),
                patch.object(
                    watchdog,
                    "safe_operator_restart",
                    return_value=(
                        "restarted",
                        watchdog.ProbeResult(
                            "healthy", pid=456, age_seconds=1.0
                        ),
                        {"bounded": True},
                    ),
                ),
                patch.object(watchdog, "restart_service"),
                patch.object(watchdog, "emit"),
                patch.object(watchdog.time, "sleep"),
                patch.object(watchdog.time, "monotonic", side_effect=itertools.repeat(0.0)),
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.chain([1000.0], itertools.repeat(1001.0)),
                ),
            ):
                self.assertEqual(0, watchdog.run_watchdog(args))
            state = watchdog.load_state(Path(tmp) / "operator-watchdog-state.json")
            self.assertEqual(0, state.consecutive_failures)
            self.assertEqual(0, state.backoff_level)
            self.assertEqual(0, state.next_restart_not_before)
            self.assertEqual(1, state.restart_generation)
            self.assertEqual([1000], state.restart_timestamps)

    def test_tunnel_stale_poll_golden_recovery_is_single_restart_and_convergence_gated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "tunnel-watchdog-state.json"
            watchdog.save_state(
                state_path, watchdog.WatchdogState(consecutive_failures=2)
            )
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "tunnel",
                        "--state-dir",
                        tmp,
                        "--failure-threshold",
                        "3",
                        "--startup-grace",
                        "0",
                        "--recovery-timeout",
                        "1",
                    ]
                )
            )
            stale = watchdog.ProbeResult(
                "unhealthy",
                ("control-plane-poll-stale",),
                pid=123,
                age_seconds=300.0,
                start_ticks=10,
            )
            healthy = watchdog.ProbeResult(
                "healthy", pid=456, age_seconds=1.0, start_ticks=20
            )

            def passthrough(probe, state, **_kwargs):
                return probe, state

            with (
                patch.object(watchdog, "probe_component", return_value=stale),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(watchdog, "restart_service") as restart,
                patch.object(
                    watchdog,
                    "runtime_deployment_identity",
                    return_value={
                        "release_id": "test-release",
                        "repo_head": "a" * 40,
                    },
                ),
                patch.object(watchdog, "emit") as emit,
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(1000.0),
                ),
                patch.object(
                    watchdog.time,
                    "monotonic",
                    side_effect=iter([0.0, 2.0]),
                ),
            ):
                self.assertEqual(4, watchdog.run_watchdog(args))

            restart.assert_called_once_with("tunnel-client-grabowski.service")
            state = watchdog.load_state(state_path)
            self.assertTrue(state.recovery_episode_restart_attempted)
            self.assertEqual("degraded", state.recovery_phase)
            self.assertEqual(1, state.restart_generation)
            restarting = next(
                call
                for call in emit.call_args_list
                if call.args[0] == "grabowski.component_watchdog.restarting"
            )
            self.assertEqual("watchdog", restarting.kwargs["initiator"])
            self.assertEqual(
                "control-plane-poll-stale", restarting.kwargs["recovery_reason"]
            )
            self.assertEqual("restarting", restarting.kwargs["recovery_phase"])
            self.assertEqual("a" * 40, restarting.kwargs["repo_head"])

            with (
                patch.object(watchdog, "probe_component", return_value=stale),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(watchdog, "restart_service") as second_restart,
                patch.object(
                    watchdog,
                    "runtime_deployment_identity",
                    return_value={
                        "release_id": "test-release",
                        "repo_head": "a" * 40,
                    },
                ),
                patch.object(watchdog, "emit") as second_emit,
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(1100.0),
                ),
            ):
                self.assertEqual(1, watchdog.run_watchdog(args))

            second_restart.assert_not_called()
            self.assertEqual(
                "grabowski.component_watchdog.restart_deferred",
                second_emit.call_args.args[0],
            )
            self.assertEqual(
                "recovery-episode-restart-already-attempted",
                second_emit.call_args.kwargs["reason"],
            )

            with (
                patch.object(watchdog, "probe_component", return_value=healthy),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(
                    watchdog,
                    "refresh_connector_snapshot_from_runtime",
                    return_value={"state": "error", "reason": "discover-failed"},
                ),
                patch.object(watchdog, "restart_service") as recovering_restart,
                patch.object(watchdog, "emit") as recovering_emit,
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(1200.0),
                ),
            ):
                self.assertEqual(1, watchdog.run_watchdog(args))

            recovering_restart.assert_not_called()
            state = watchdog.load_state(state_path)
            self.assertTrue(state.recovery_episode_restart_attempted)
            self.assertEqual("connector-convergence", state.recovery_phase)
            self.assertEqual(
                "grabowski.component_watchdog.recovering",
                recovering_emit.call_args.args[0],
            )

            with (
                patch.object(watchdog, "probe_component", return_value=healthy),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(
                    watchdog,
                    "refresh_connector_snapshot_from_runtime",
                    return_value={"state": "not_due"},
                ),
                patch.object(watchdog, "restart_service") as healthy_restart,
                patch.object(watchdog, "emit") as healthy_emit,
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(1300.0),
                ),
            ):
                self.assertEqual(0, watchdog.run_watchdog(args))

            healthy_restart.assert_not_called()
            state = watchdog.load_state(state_path)
            self.assertFalse(state.recovery_episode_restart_attempted)
            self.assertEqual(0, state.recovery_episode_started_at_unix)
            self.assertEqual("idle", state.recovery_phase)
            self.assertEqual(
                "grabowski.component_watchdog.healthy",
                healthy_emit.call_args.args[0],
            )

    def test_tunnel_recovered_event_preserves_pre_reset_episode_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "tunnel",
                        "--state-dir",
                        tmp,
                        "--failure-threshold",
                        "1",
                        "--startup-grace",
                        "0",
                        "--recovery-timeout",
                        "5",
                    ]
                )
            )
            stale = watchdog.ProbeResult(
                "unhealthy",
                ("control-plane-poll-stale",),
                pid=123,
                age_seconds=300.0,
                start_ticks=10,
            )
            healthy = watchdog.ProbeResult(
                "healthy", pid=456, age_seconds=1.0, start_ticks=20
            )

            def passthrough(probe, state, **_kwargs):
                return probe, state

            with (
                patch.object(
                    watchdog, "probe_component", side_effect=[stale, healthy]
                ),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(watchdog, "restart_service") as restart,
                patch.object(
                    watchdog,
                    "refresh_connector_snapshot_from_runtime",
                    return_value={"state": "renewed"},
                ),
                patch.object(
                    watchdog, "runtime_deployment_identity", return_value={}
                ),
                patch.object(watchdog, "emit") as emit,
                patch.object(watchdog.time, "sleep"),
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(3000.0),
                ),
                patch.object(
                    watchdog.time,
                    "monotonic",
                    side_effect=iter([0.0, 1.0]),
                ),
            ):
                self.assertEqual(0, watchdog.run_watchdog(args))

            restart.assert_called_once_with("tunnel-client-grabowski.service")
            recovered = next(
                call
                for call in emit.call_args_list
                if call.args[0] == "grabowski.component_watchdog.recovered"
            )
            self.assertEqual("restarting", recovered.kwargs["recovery_phase"])
            self.assertEqual(
                3000, recovered.kwargs["recovery_episode_started_at_unix"]
            )
            self.assertEqual("idle", recovered.kwargs["post_recovery_phase"])
            state = watchdog.load_state(Path(tmp) / "tunnel-watchdog-state.json")
            self.assertEqual("idle", state.recovery_phase)
            self.assertEqual(0, state.recovery_episode_started_at_unix)
            self.assertFalse(state.recovery_episode_restart_attempted)

    def test_tunnel_restart_failure_does_not_loop_within_episode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "tunnel-watchdog-state.json"
            watchdog.save_state(
                state_path, watchdog.WatchdogState(consecutive_failures=2)
            )
            args = watchdog.normalize_args(
                watchdog.parser().parse_args(
                    [
                        "--component",
                        "tunnel",
                        "--state-dir",
                        tmp,
                        "--failure-threshold",
                        "3",
                        "--startup-grace",
                        "0",
                    ]
                )
            )
            stale = watchdog.ProbeResult(
                "unhealthy", ("control-plane-poll-stale",), pid=123, start_ticks=10
            )

            def passthrough(probe, state, **_kwargs):
                return probe, state

            with (
                patch.object(watchdog, "probe_component", return_value=stale),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(
                    watchdog,
                    "restart_service",
                    side_effect=watchdog.WatchdogError("service-restart-failed: test"),
                ) as restart,
                patch.object(watchdog, "runtime_deployment_identity", return_value={}),
                patch.object(watchdog, "emit"),
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(2000.0),
                ),
            ):
                self.assertEqual(4, watchdog.run_watchdog(args))

            self.assertEqual(1, restart.call_count)
            state = watchdog.load_state(state_path)
            self.assertTrue(state.recovery_episode_restart_attempted)
            self.assertEqual("degraded", state.recovery_phase)

            with (
                patch.object(watchdog, "probe_component", return_value=stale),
                patch.object(
                    watchdog,
                    "classify_tunnel_readiness_dependency",
                    side_effect=passthrough,
                ),
                patch.object(watchdog, "restart_service") as retry,
                patch.object(watchdog, "runtime_deployment_identity", return_value={}),
                patch.object(watchdog, "emit"),
                patch.object(
                    watchdog.time,
                    "time",
                    side_effect=itertools.repeat(2100.0),
                ),
            ):
                self.assertEqual(1, watchdog.run_watchdog(args))
            retry.assert_not_called()



if __name__ == "__main__":
    unittest.main()

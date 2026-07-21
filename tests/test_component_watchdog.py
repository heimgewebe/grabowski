import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "component_watchdog.py"

spec = importlib.util.spec_from_file_location("component_watchdog_test", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("component watchdog could not be loaded")
watchdog = importlib.util.module_from_spec(spec)
sys.modules["component_watchdog_test"] = watchdog
spec.loader.exec_module(watchdog)

HEALTH_PAYLOAD = {"healthy": True, "audit_valid": True}


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

    def test_runtime_unhealthy_is_indeterminate_not_restartable(self) -> None:
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
        self.assertEqual("indeterminate", result.status)
        self.assertEqual(("mcp-runtime-unhealthy",), result.reasons)

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
        self.assertEqual(("mcp-stdio-process-exited",), result.reasons)

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
            original = watchdog.WatchdogState(1, [10, 20], 4, 5000, 9)
            watchdog.save_state(path, original)
            self.assertEqual(original, watchdog.load_state(path))


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
                patch.object(watchdog, "restart_service"),
                patch.object(watchdog, "emit"),
                patch.object(watchdog.time, "sleep"),
                patch.object(watchdog.time, "monotonic", side_effect=[0.0, 0.0]),
                patch.object(watchdog.time, "time", side_effect=[1000.0, 1001.0]),
            ):
                self.assertEqual(0, watchdog.run_watchdog(args))
            state = watchdog.load_state(Path(tmp) / "operator-watchdog-state.json")
            self.assertEqual(0, state.consecutive_failures)
            self.assertEqual(0, state.backoff_level)
            self.assertEqual(0, state.next_restart_not_before)
            self.assertEqual(1, state.restart_generation)
            self.assertEqual([1000], state.restart_timestamps)


if __name__ == "__main__":
    unittest.main()

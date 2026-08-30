from pathlib import Path
import ast
import hashlib
import importlib.util
import inspect
import json
import os
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "grabowski_operator.py"


def _real_capability_catalog() -> tuple[str, ...]:
    """The canonical capability catalog, read from the module that defines it."""
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    import grabowski_mcp

    return tuple(grabowski_mcp.ALL_CAPABILITIES)


class _FakeAsyncLock:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        self.settings = types.SimpleNamespace(
            log_level="INFO",
            stateless_http=False,
        )
        self.session_manager = types.SimpleNamespace(
            session_idle_timeout=None,
            _session_creation_lock=_FakeAsyncLock(),
            stateless=False,
        )
        self._registered_tools = {
            name: types.SimpleNamespace(
                is_async=False,
                context_kwarg=None,
                annotations=types.SimpleNamespace(readOnlyHint=True),
            )
            for name in ("read", "write")
        }

        async def call_tool(*args, **kwargs):
            return {
                "called": True,
                "args": args,
                "kwargs": kwargs,
                "thread_id": threading.get_ident(),
            }

        self._tool_manager = types.SimpleNamespace(
            call_tool=call_tool,
            get_tool=self._registered_tools.get,
        )



    def tool(self, *args, **kwargs):
        return lambda function: function

    def custom_route(self, *args, **kwargs):
        return lambda function: function

    def streamable_http_app(self):
        self.session_manager.stateless = self.settings.stateless_http
        return object()


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs
        self.readOnlyHint = kwargs.get("readOnlyHint")


def _load_operator_module():
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_base = types.ModuleType("grabowski_mcp")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    fake_base.mcp = _FakeFastMCP()

    def load_policy():
        return {
            "active_profile": "operator",
            "forbidden_capabilities": [],
            "profiles": {
                "operator": {
                    "capabilities": [
                        "terminal_execute",
                        "durable_job",
                        "git_cli",
                        "github_cli",
                        "user_service_control",
                        "tmux_interaction",
                        "process_inspect",
                        "process_signal",
                        "port_inspect",
                        "privileged_reference",
                    ],
                },
            },
        }

    def active_profile(policy):
        return {
            "name": "operator",
            **policy["profiles"]["operator"],
        }

    fake_base._load_policy = load_policy
    fake_base._active_profile = active_profile
    fake_base._resolve_existing = (
        lambda raw_path, kind: Path(raw_path).expanduser().resolve(strict=True)
    )
    # The capability catalog has exactly one definition, and the double must be
    # bound to it rather than restate it: a stand-in that drifts from the real
    # catalog would let a capability regression pass unnoticed here.
    fake_base.ALL_CAPABILITIES = _real_capability_catalog()

    def effective_capabilities(policy):
        forbidden = set(policy.get("forbidden_capabilities", []))
        return {
            capability
            for capability in active_profile(policy).get("capabilities", [])
            if isinstance(capability, str) and capability not in forbidden
        }

    fake_base._effective_capabilities = effective_capabilities
    fake_base._kill_switch_state = lambda: {"engaged": False}
    fake_base.KILL_SWITCH_PATH = Path(
        "/home/alex/.local/state/grabowski/operator-kill-switch"
    )
    fake_base._require_blockade_allows_mutation = lambda capability, **kwargs: None
    fake_base._require_valid_audit_chain = lambda: None
    fake_base._reject_forbidden_hosts_in_argv = lambda argv, *, policy=None: None

    def read_bound_regular_bytes(path, max_bytes):
        path = Path(path)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PermissionError("not one regular file")
        payload = path.read_bytes()
        if len(payload) > max_bytes:
            raise ValueError("file too large")
        return {
            "data": payload,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "mode": stat.S_IMODE(metadata.st_mode),
            "mtime_ns": metadata.st_mtime_ns,
            "ctime_ns": metadata.st_ctime_ns,
            "dev": metadata.st_dev,
            "ino": metadata.st_ino,
        }

    fake_base._read_bound_regular_bytes = read_bound_regular_bytes
    fake_base._append_audit = lambda record: None
    fake_base._retain_pending_transport_target = (
        lambda challenge_receipt_sha256, **kwargs: {
            "challenge_receipt_sha256": challenge_receipt_sha256,
            "target_tool_name": kwargs.get("tool_name"),
            "target_arguments_sha256": kwargs.get("arguments_sha256"),
            "replayed": False,
        }
    )

    module_name = "grabowski_operator_contract_test"
    spec = importlib.util.spec_from_file_location(
        module_name,
        SOURCE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load grabowski_operator")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(
        sys.modules,
        {
            "mcp": fake_mcp,
            "mcp.server": fake_server,
            "mcp.server.fastmcp": fake_fastmcp,
            "mcp.types": fake_types,
            "grabowski_mcp": fake_base,
            module_name: module,
        },
        clear=False,
    ):
        spec.loader.exec_module(module)
    return module


class OperatorContractTests(unittest.TestCase):
    def test_operator_source_compiles(self) -> None:
        tree = ast.parse(
            SOURCE.read_text(encoding="utf-8"),
            filename=str(SOURCE),
        )
        self.assertIsInstance(tree, ast.Module)

    def test_managed_runtime_environment_is_xdg_bound_and_fail_closed(self) -> None:
        operator = _load_operator_module()
        managed = operator._managed_runtime_environment(
            {
                "XDG_RUNTIME_DIR": "/run/user/1000",
                "HEIM_NODE_RUNTIME_ENV_DIR": "/stale/node",
                "UV_CACHE_DIR": "/stale/uv",
            }
        )
        self.assertEqual(
            {
                "XDG_RUNTIME_DIR": "/run/user/1000",
                "HEIM_NODE_RUNTIME_ENV_DIR": "/run/user/1000/grabowski-node-runtime-env",
                "UV_CACHE_DIR": "/run/user/1000/grabowski-uv-cache",
            },
            managed,
        )
        self.assertEqual({}, operator._managed_runtime_environment({}))
        with self.assertRaisesRegex(RuntimeError, "explicit XDG_RUNTIME_DIR"):
            operator._managed_runtime_environment(
                {"HEIM_NODE_RUNTIME_ENV_DIR": "/stale/node"}
            )
        with self.assertRaisesRegex(RuntimeError, "explicit XDG_RUNTIME_DIR"):
            operator._managed_runtime_environment({"UV_CACHE_DIR": "/stale/uv"})
        with self.assertRaisesRegex(RuntimeError, "absolute normalized path"):
            operator._managed_runtime_environment({"XDG_RUNTIME_DIR": "relative/runtime"})
        for root in ("/", "//"):
            with self.subTest(root=root), self.assertRaisesRegex(
                RuntimeError, "filesystem root"
            ):
                operator._managed_runtime_environment({"XDG_RUNTIME_DIR": root})

    def test_safe_environment_overrides_stale_managed_runtime_paths(self) -> None:
        operator = _load_operator_module()
        with patch.dict(
            operator.os.environ,
            {
                "XDG_RUNTIME_DIR": "/run/user/1000",
                "HEIM_NODE_RUNTIME_ENV_DIR": "/stale/node",
                "UV_CACHE_DIR": "/stale/uv",
            },
            clear=False,
        ):
            environment = operator._safe_environment()
        self.assertEqual(
            "/run/user/1000/grabowski-node-runtime-env",
            environment["HEIM_NODE_RUNTIME_ENV_DIR"],
        )
        self.assertEqual(
            "/run/user/1000/grabowski-uv-cache",
            environment["UV_CACHE_DIR"],
        )

    def test_http_recovery_contract_is_loopback_bound(self) -> None:
        operator = _load_operator_module()
        metadata = operator._protected_resource_metadata(
            "http://127.0.0.1:18181/"
        )
        self.assertEqual("http://127.0.0.1:18181/mcp", metadata["resource"])
        self.assertEqual([], metadata["authorization_servers"])
        self.assertEqual([], metadata["bearer_methods_supported"])
        with self.assertRaisesRegex(RuntimeError, "loopback HTTP"):
            operator._protected_resource_metadata("https://example.com/")

    def test_deployment_admission_status_route_is_registered(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"), filename=str(SOURCE))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef)
            and node.name == "deployment_admission_status"
        )
        decorators = [
            decorator
            for decorator in function.decorator_list
            if isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Name)
            and decorator.func.id == "_mcp_custom_route"
        ]
        self.assertEqual(1, len(decorators))
        self.assertIsInstance(decorators[0].args[0], ast.Name)
        self.assertEqual(
            "DEPLOYMENT_ADMISSION_STATUS_PATH", decorators[0].args[0].id
        )

    def test_http_transport_is_stateless_and_liveness_lock_is_bounded(self) -> None:
        operator = _load_operator_module()
        operator._configure_http_runtime()
        self.assertTrue(operator.HTTP_STATELESS_MODE)
        self.assertTrue(operator.mcp.settings.stateless_http)
        self.assertEqual("WARNING", operator.HTTP_LOG_LEVEL)
        self.assertEqual(operator.HTTP_LOG_LEVEL, operator.mcp.settings.log_level)
        self.assertTrue(operator.mcp.session_manager.stateless)
        self.assertIsNone(operator.mcp.session_manager.session_idle_timeout)
        self.assertEqual(
            {
                "mcp.server.lowlevel.server",
                "mcp.server.streamable_http",
                "mcp.server.streamable_http_manager",
            },
            set(operator.HTTP_TRANSPORT_VERBOSE_LOGGERS),
        )
        for logger_name in operator.HTTP_TRANSPORT_VERBOSE_LOGGERS:
            self.assertEqual(
                operator.logging.WARNING,
                operator.logging.getLogger(logger_name).level,
            )
        self.assertTrue(
            operator.asyncio.run(
                operator._session_creation_lock_available(
                    operator.MCP_SESSION_LOCK_PROBE_TIMEOUT_SECONDS
                )
            )
        )
        self.assertEqual("/_grabowski/mcp-liveness", operator.MCP_LIVENESS_PATH)

    def test_deployment_admission_marker_is_private_bounded_and_expiring(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "deployment-admission-drain.json"
            payload = {
                "schema_version": 1,
                "kind": operator.DEPLOYMENT_ADMISSION_MARKER_KIND,
                "token": "a" * 64,
                "expected_head": "b" * 40,
                "source_identity_sha256": "c" * 64,
                "created_at_unix": 100,
                "expires_at_unix": 200,
            }
            marker.write_text(json.dumps(payload), encoding="utf-8")
            marker.chmod(0o600)
            with patch.object(operator, "DEPLOYMENT_ADMISSION_MARKER_PATH", marker):
                active = operator._read_deployment_admission_marker(now_unix=150)
                expired = operator._read_deployment_admission_marker(now_unix=201)
                marker.chmod(0o644)
                invalid = operator._read_deployment_admission_marker(now_unix=150)
                marker.unlink()
                target = Path(directory) / "target"
                target.write_text(json.dumps(payload), encoding="utf-8")
                marker.symlink_to(target)
                symlink = operator._read_deployment_admission_marker(now_unix=150)
        self.assertEqual("active", active["state"])
        self.assertTrue(active["active"])
        self.assertEqual("expired", expired["state"])
        self.assertFalse(expired["active"])
        self.assertEqual("invalid", invalid["state"])
        self.assertTrue(invalid["active"])
        self.assertEqual("invalid", symlink["state"])
        self.assertTrue(symlink["active"])


    def test_deployment_admission_gate_rejects_new_tools_before_effect(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "deployment-admission-drain.json"
            payload = {
                "schema_version": 1,
                "kind": operator.DEPLOYMENT_ADMISSION_MARKER_KIND,
                "token": "a" * 64,
                "expected_head": "b" * 40,
                "source_identity_sha256": "c" * 64,
                "created_at_unix": int(time.time()) - 1,
                "expires_at_unix": int(time.time()) + 60,
            }
            marker.write_text(json.dumps(payload), encoding="utf-8")
            marker.chmod(0o600)
            with patch.object(operator, "DEPLOYMENT_ADMISSION_MARKER_PATH", marker):
                operator._configure_http_runtime()
                with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                    operator.asyncio.run(
                        operator.mcp._tool_manager.call_tool("write", {})
                    )
                self.assertEqual(0, operator._deployment_admission_active_tool_calls())
                marker.unlink()
                result = operator.asyncio.run(
                    operator.mcp._tool_manager.call_tool("read", {})
                )
        self.assertTrue(result["called"])
        self.assertTrue(operator._DEPLOYMENT_ADMISSION_GATE_INSTALLED)

    def test_cold_reentry_tools_wait_for_active_marker_then_reenter_after_expiry(
        self,
    ) -> None:
        operator = _load_operator_module()
        tool_names = (
            "grabowski_recovery_provenance_repair",
            "grabowski_runtime_deploy_schedule",
        )
        for name in tool_names:
            operator.mcp._registered_tools[name] = types.SimpleNamespace(
                is_async=False,
                context_kwarg=None,
                annotations=types.SimpleNamespace(readOnlyHint=False),
            )
        now = int(time.time())
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "deployment-admission-drain.json"
            payload = {
                "schema_version": 1,
                "kind": operator.DEPLOYMENT_ADMISSION_MARKER_KIND,
                "token": "a" * 64,
                "expected_head": "b" * 40,
                "source_identity_sha256": "c" * 64,
                "created_at_unix": now - 60,
                "expires_at_unix": now + 60,
            }
            marker.write_text(json.dumps(payload), encoding="utf-8")
            marker.chmod(0o600)
            with (
                patch.object(operator, "DEPLOYMENT_ADMISSION_MARKER_PATH", marker),
                patch.object(
                    operator, "_require_transport_roundtrip_for_tool", return_value=None
                ) as transport_gate,
            ):
                operator._configure_http_runtime()
                for name in tool_names:
                    with self.subTest(tool=name, marker="active"):
                        with self.assertRaisesRegex(
                            RuntimeError, "rejects new tool calls"
                        ):
                            operator.asyncio.run(
                                operator.mcp._tool_manager.call_tool(
                                    name, {"expected_head": "b" * 40}
                                )
                            )
                transport_gate.assert_not_called()

                payload["expires_at_unix"] = now - 1
                marker.write_text(json.dumps(payload), encoding="utf-8")
                marker.chmod(0o600)
                for name in tool_names:
                    with self.subTest(tool=name, marker="expired"):
                        result = operator.asyncio.run(
                            operator.mcp._tool_manager.call_tool(
                                name, {"expected_head": "b" * 40}
                            )
                        )
                        self.assertTrue(result["called"])

        self.assertEqual(transport_gate.call_count, len(tool_names))
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_deployment_admission_gate_offloads_sync_tools_from_event_loop(self) -> None:
        operator = _load_operator_module()
        caller_thread = threading.get_ident()
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg="ctx",
            annotations=types.SimpleNamespace(readOnlyHint=True),
        )
        operator._configure_http_runtime()
        result = operator.asyncio.run(
            operator.mcp._tool_manager.call_tool("read", {})
        )
        self.assertTrue(result["called"])
        self.assertNotEqual(caller_thread, result["thread_id"])
        self.assertEqual(8, operator.SYNC_TOOL_EXECUTOR_MAX_WORKERS)

    def test_cancelled_sync_tool_remains_admission_active_until_worker_finishes(self) -> None:
        operator = _load_operator_module()
        started = threading.Event()
        release = threading.Event()

        async def slow_call_tool(*args, **kwargs):
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test worker release timed out")
            return {"called": True, "args": args, "kwargs": kwargs}

        operator.mcp._tool_manager.call_tool = slow_call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg=None,
            annotations=types.SimpleNamespace(readOnlyHint=True),
        )
        operator._configure_http_runtime()

        async def exercise() -> None:
            call = operator.asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {})
            )
            started_ok = await operator.asyncio.to_thread(started.wait, 2)
            self.assertTrue(started_ok)
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            call.cancel()
            with self.assertRaises(operator.asyncio.CancelledError):
                await call
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            release.set()
            for _attempt in range(100):
                if operator._deployment_admission_active_tool_calls() == 0:
                    break
                await operator.asyncio.sleep(0.01)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

        operator.asyncio.run(exercise())

    def test_cancelled_queued_sync_tool_never_executes_and_releases_admission(self) -> None:
        operator = _load_operator_module()
        started = threading.Event()
        release = threading.Event()
        executed: list[int] = []
        executor = operator.concurrent.futures.ThreadPoolExecutor(max_workers=1)
        operator._SYNC_TOOL_EXECUTOR = executor

        async def slow_call_tool(_name, arguments):
            executed.append(arguments["slot"])
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test worker release timed out")
            return {"called": True, "slot": arguments["slot"]}

        operator.mcp._tool_manager.call_tool = slow_call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg=None,
            annotations=types.SimpleNamespace(readOnlyHint=True),
        )
        operator._configure_http_runtime()

        async def exercise() -> None:
            running = operator.asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {"slot": 1})
            )
            started_ok = await operator.asyncio.to_thread(started.wait, 2)
            self.assertTrue(started_ok)
            queued = operator.asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {"slot": 2})
            )
            await operator.asyncio.sleep(0)
            self.assertEqual(2, operator._deployment_admission_active_tool_calls())
            queued.cancel()
            with self.assertRaises(operator.asyncio.CancelledError):
                await queued
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            release.set()
            self.assertEqual(1, (await running)["slot"])
            for _attempt in range(100):
                if operator._deployment_admission_active_tool_calls() == 0:
                    break
                await operator.asyncio.sleep(0.01)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())
            self.assertEqual([1], executed)

        try:
            operator.asyncio.run(exercise())
        finally:
            release.set()
            executor.shutdown(wait=True, cancel_futures=True)

    def test_deployment_admission_gate_keeps_async_tools_on_event_loop(self) -> None:
        operator = _load_operator_module()
        caller_thread = threading.get_ident()
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=True,
            context_kwarg=None,
            annotations=types.SimpleNamespace(readOnlyHint=True),
        )
        operator._configure_http_runtime()
        result = operator.asyncio.run(
            operator.mcp._tool_manager.call_tool("read", {})
        )
        self.assertTrue(result["called"])
        self.assertEqual(caller_thread, result["thread_id"])


    def test_liveness_probe_times_out_on_held_session_creation_lock(self) -> None:
        operator = _load_operator_module()

        class BusyLock:
            async def __aenter__(self):
                await operator.asyncio.sleep(60)
                return self

            async def __aexit__(self, exc_type, exc, traceback):
                return False

        operator.mcp.session_manager._session_creation_lock = BusyLock()
        self.assertFalse(
            operator.asyncio.run(
                operator._session_creation_lock_available(0.01)
            )
        )

    def test_http_runtime_fails_closed_without_required_fastmcp_contract(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator.mcp, "custom_route", None):
            with self.assertRaisesRegex(RuntimeError, "custom_route"):
                operator._configure_http_runtime()
        operator.mcp.session_manager._session_creation_lock = None
        with self.assertRaisesRegex(RuntimeError, "session creation lock"):
            operator._configure_http_runtime()

    def test_stack_dump_memfd_is_fixed_and_sealed(self) -> None:
        operator = _load_operator_module()
        stream = operator._open_stack_dump_memfd(4096)
        try:
            descriptor = stream.fileno()
            self.assertEqual(4096, operator.os.fstat(descriptor).st_size)
            seals = operator.fcntl.fcntl(
                descriptor, operator.fcntl.F_GET_SEALS
            )
            self.assertTrue(seals & operator.fcntl.F_SEAL_GROW)
            self.assertTrue(seals & operator.fcntl.F_SEAL_SHRINK)
            stream.write(b"bounded")
            self.assertEqual(
                len(b"bounded"),
                operator.os.lseek(descriptor, 0, operator.os.SEEK_CUR),
            )
            with self.assertRaises(OSError):
                operator.os.ftruncate(descriptor, 8192)
        finally:
            stream.close()

    def test_operator_registers_recovery_stack_signal(self) -> None:
        operator = _load_operator_module()
        stream = MagicMock()
        with (
            patch.object(operator, "_open_stack_dump_memfd", return_value=stream),
            patch.object(operator.faulthandler, "enable") as enable,
            patch.object(operator.faulthandler, "register") as register,
        ):
            operator._configure_faulthandler()
        enable.assert_called_once_with(all_threads=True)
        register.assert_called_once_with(
            operator.signal.SIGUSR1,
            file=stream,
            all_threads=True,
            chain=False,
        )
        self.assertIs(operator._STACK_DUMP_FILE, stream)

    def test_runtime_deploy_runner_is_reserved_for_typed_scheduler(self) -> None:
        operator = _load_operator_module()
        repo = operator.HOME / "repos" / "grabowski"
        runner = "tools/run_scheduled_deploy.py"
        commands = [
            ["/usr/bin/python3", runner, "--expected-head", "a" * 40],
            ["python3", runner],
            ["/usr/bin/env", "python3", runner],
            ["bash", "-c", f"python3 {runner} --expected-head {'a' * 40}"],
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(
                    operator._reserved_runtime_deploy_command(command, repo)
                )
        self.assertFalse(
            operator._reserved_runtime_deploy_command(
                ["python3", "-c", "print(1)"],
                repo,
            )
        )

    def test_expected_tools_are_declared(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        declared = set()

        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                function = decorator.func
                if not (
                    isinstance(function, ast.Attribute)
                    and function.attr == "tool"
                ):
                    continue
                for keyword in decorator.keywords:
                    if (
                        keyword.arg == "name"
                        and isinstance(keyword.value, ast.Constant)
                    ):
                        declared.add(keyword.value.value)

        expected = {
            "grabowski_terminal_run",
            "grabowski_job_start",
            "grabowski_job_status",
            "grabowski_job_notification_list",
            "grabowski_job_notification_ack",
            "grabowski_job_logs",
            "grabowski_job_cancel",
            "grabowski_git",
            "grabowski_github",
            "grabowski_user_service",
            "grabowski_tmux_list",
            "grabowski_tmux_capture",
            "grabowski_tmux_send",
            "grabowski_process_list",
            "grabowski_process_signal",
            "grabowski_ports",
            "grabowski_privileged_action_reference",
        }
        self.assertEqual(expected, declared)

    def test_heavy_read_surfaces_offload_from_the_mcp_event_loop(self) -> None:
        tree = ast.parse(
            (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        )
        expected = {
            "grabowski_current_work",
            "grabowski_operator_optimization_report",
            "grabowski_checkout_binding_reconciliation",
        }
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name in expected
        }
        self.assertEqual(expected, set(functions))
        for name, function in functions.items():
            with self.subTest(name=name):
                calls = [
                    node
                    for node in ast.walk(function)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "asyncio"
                    and node.func.attr == "to_thread"
                ]
                self.assertEqual(1, len(calls))
                self.assertTrue(
                    any(isinstance(node, ast.Await) for node in ast.walk(function))
                )

    def test_bureau_pickup_runtime_capability_contract(self) -> None:
        runtime = (ROOT / "src" / "grabowski_runtime.py").read_text(encoding="utf-8")
        self.assertIn("import grabowski_bureau_pickup", runtime)

        contract = json.loads(
            (ROOT / "config" / "runtime-entrypoint.json").read_text(encoding="utf-8")
        )
        pickup_tools = {
            "grabowski_bureau_pickup_execute",
            "grabowski_bureau_pickup_status",
            "grabowski_bureau_pickup_release",
        }
        self.assertTrue(pickup_tools.issubset(set(contract["expected_tools"])))
        supporting = {
            item["module"]: item["source"] for item in contract["supporting_sources"]
        }
        self.assertEqual(
            supporting["grabowski_bureau_pickup"],
            "src/grabowski_bureau_pickup.py",
        )

        tree = ast.parse(
            (ROOT / "src" / "grabowski_mcp.py").read_text(encoding="utf-8")
        )
        assignments: dict[str, object] = {}
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in {
                    "TOOL_CAPABILITY_REQUIREMENTS",
                    "OPERATOR_CAPABILITY_REQUIREMENT_TOOLS",
                }
            ):
                assignments[node.targets[0].id] = ast.literal_eval(node.value)
        requirements = assignments["TOOL_CAPABILITY_REQUIREMENTS"]
        operator_tools = assignments["OPERATOR_CAPABILITY_REQUIREMENT_TOOLS"]
        self.assertEqual(
            requirements["grabowski_bureau_pickup_execute"],
            ("resource_lease", "terminal_execute"),
        )
        self.assertEqual(requirements["grabowski_bureau_pickup_status"], ())
        self.assertEqual(
            requirements["grabowski_bureau_pickup_release"],
            ("resource_lease", "terminal_execute"),
        )
        self.assertIn("grabowski_bureau_pickup_execute", operator_tools)
        self.assertIn("grabowski_bureau_pickup_release", operator_tools)
        self.assertNotIn("grabowski_bureau_pickup_status", operator_tools)

        capability_tree = ast.parse(
            (ROOT / "src" / "grabowski_capabilities.py").read_text(encoding="utf-8")
        )
        profiles: dict[str, object] = {}
        for node in ast.walk(capability_tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "TOOL_PROFILES"
                and node.func.attr == "update"
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Dict)
            ):
                profiles.update(ast.literal_eval(node.args[0]))
        self.assertEqual(profiles["grabowski_bureau_pickup_execute"]["risk_class"], "high")
        self.assertEqual(profiles["grabowski_bureau_pickup_status"]["effects"], [])
        self.assertEqual(
            profiles["grabowski_bureau_pickup_release"]["reversibility"],
            "terminal-bound-idempotent-release",
        )

    def test_policy_no_longer_forbids_operator_core(self) -> None:
        policy = json.loads(
            (
                ROOT / "config" / "access.example.json"
            ).read_text(encoding="utf-8")
        )
        forbidden = set(policy["forbidden_capabilities"])
        self.assertNotIn("shell_execute", forbidden)
        self.assertNotIn("git_mutate", forbidden)
        self.assertNotIn("service_control", forbidden)

    def test_privilege_escalation_is_explicitly_blocked(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        for command in ("sudo", "su", "pkexec", "doas"):
            self.assertIn(command, source)

    def test_evidence_root_is_guarded(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('HOME / "repos" / "merges"', source)
        self.assertIn("immutable evidence", source)

    def test_synchronous_commands_have_bounded_runtime(self) -> None:
        tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
        assignments = {}
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                assignments[target.id] = node.value.value
        self.assertEqual(60, assignments.get("DEFAULT_TIMEOUT"))
        self.assertEqual(120, assignments.get("MAX_TIMEOUT"))

    def test_synchronous_call_shape_allows_bounded_direct_argv(self) -> None:
        operator = _load_operator_module()
        receipt = operator._synchronous_call_shape_receipt(
            ["printf", "ok"],
            timeout_seconds=30,
            max_output_bytes=64 * 1024,
            surface="test",
        )
        self.assertTrue(receipt["allowed"])
        self.assertIsNone(receipt["required_route"])
        self.assertFalse(receipt["process_started"])

    def test_synchronous_call_shape_denies_shell_composition_before_start(self) -> None:
        operator = _load_operator_module()
        with self.assertRaises(operator.SynchronousCallShapeDenied) as raised:
            operator._enforce_synchronous_call_shape(
                ["env", "MODE=test", "bash", "-lc", "printf ok"],
                timeout_seconds=30,
                max_output_bytes=64 * 1024,
                surface="grabowski_terminal_run",
            )
        receipt = raised.exception.receipt
        self.assertEqual(receipt["required_route"], "durable_task")
        self.assertIn("shell_composition_requires_durable_task", receipt["reason_codes"])
        self.assertFalse(receipt["process_started"])
        self.assertIn('"required_route":"durable_task"', str(raised.exception))

    def test_synchronous_call_shape_denies_known_shell_launchers(self) -> None:
        operator = _load_operator_module()
        examples = [
            ["busybox", "sh", "-c", "printf ok"],
            ["docker", "exec", "container", "sh", "-c", "printf ok"],
            ["ssh", "host", "bash", "-lc", "printf ok"],
            ["ssh", "host", "bash -lc 'printf ok'"],
            ["docker", "exec", "container", "sh -c 'printf ok'"],
            ["systemd-run", "--user", "bash", "-lc", "printf ok"],
            ["sudo", "bash", "-lc", "printf ok"],
            ["doas", "sh", "-c", "printf ok"],
            ["pkexec", "bash", "-lc", "printf ok"],
            ["su", "-c", "sh -c 'printf ok'"],
            ["watch", "bash", "-lc", "printf ok"],
            ["script", "-c", "bash -lc 'printf ok'", "/dev/null"],
        ]
        for command in examples:
            with self.subTest(command=command):
                receipt = operator._synchronous_call_shape_receipt(
                    command,
                    timeout_seconds=30,
                    max_output_bytes=1024,
                    surface="test",
                )
                self.assertFalse(receipt["allowed"])
                self.assertEqual(receipt["required_route"], "durable_task")

    def test_synchronous_call_shape_denies_indirect_or_detaching_launchers(self) -> None:
        operator = _load_operator_module()
        examples = [
            ["ssh", "host", "uptime"],
            ["systemd-run", "--user", "sleep", "60"],
            ["setsid", "-f", "sleep", "60"],
            ["docker", "run", "-d", "image"],
            ["xargs", "-n1", "printf"],
            ["env", "MODE=test", "ssh", "host", "uptime"],
            ["timeout", "10", "systemd-run", "--user", "sleep", "60"],
            ["stdbuf", "-oL", "printf", "ok"],
            ["sudo", "printf", "ok"],
            ["doas", "printf", "ok"],
            ["pkexec", "printf", "ok"],
            ["su", "root"],
            ["watch", "printf", "ok"],
            ["script", "-c", "printf ok", "/dev/null"],
        ]
        for command in examples:
            with self.subTest(command=command):
                receipt = operator._synchronous_call_shape_receipt(
                    command,
                    timeout_seconds=30,
                    max_output_bytes=1024,
                    surface="test",
                )
                self.assertFalse(receipt["allowed"])
                self.assertEqual(receipt["required_route"], "durable_task")
                self.assertIn(
                    "indirect_execution_requires_durable_task",
                    receipt["reason_codes"],
                )
                self.assertFalse(receipt["process_started"])


    def test_synchronous_contract_scopes_indirect_execution_claim(self) -> None:
        operator = _load_operator_module()
        contract = operator._synchronous_public_contract(surface="test")
        self.assertFalse(contract["known_wrapper_execution_allowed"])
        self.assertFalse(contract["indirect_execution_detection_complete"])
        self.assertEqual(
            contract["indirect_execution_policy"],
            "known_wrapper_executables_denied_before_start",
        )
        self.assertNotIn("indirect_execution_allowed", contract)
        self.assertIn(
            "complete_detection_of_arbitrary_indirect_execution",
            contract["does_not_establish"],
        )

    def test_synchronous_call_shape_allows_bounded_find_without_exec(self) -> None:
        operator = _load_operator_module()
        receipt = operator._synchronous_call_shape_receipt(
            ["find", ".", "-maxdepth", "1"],
            timeout_seconds=30,
            max_output_bytes=1024,
            surface="test",
        )
        self.assertTrue(receipt["allowed"])

    def test_synchronous_call_shape_allows_indirect_names_as_plain_data(self) -> None:
        operator = _load_operator_module()
        receipt = operator._synchronous_call_shape_receipt(
            ["printf", "%s %s", "env", "ssh"],
            timeout_seconds=30,
            max_output_bytes=1024,
            surface="test",
        )
        self.assertTrue(receipt["allowed"])

    def test_synchronous_call_shape_does_not_treat_shell_name_as_plain_data(self) -> None:
        operator = _load_operator_module()
        receipt = operator._synchronous_call_shape_receipt(
            ["printf", "%s", "bash"],
            timeout_seconds=30,
            max_output_bytes=1024,
            surface="test",
        )
        self.assertTrue(receipt["allowed"])

    def test_synchronous_call_shape_denies_long_timeout(self) -> None:
        operator = _load_operator_module()
        with self.assertRaises(operator.SynchronousCallShapeDenied) as raised:
            operator._enforce_synchronous_call_shape(
                ["sleep", "1"],
                timeout_seconds=31,
                max_output_bytes=1024,
                surface="grabowski_fleet_run",
            )
        self.assertEqual(raised.exception.receipt["required_route"], "durable_task")
        self.assertIn(
            "timeout_exceeds_synchronous_transport_ceiling",
            raised.exception.receipt["reason_codes"],
        )

    def test_synchronous_call_shape_denies_large_output_as_split_read(self) -> None:
        operator = _load_operator_module()
        with self.assertRaises(operator.SynchronousCallShapeDenied) as raised:
            operator._enforce_synchronous_call_shape(
                ["cat", "large.txt"],
                timeout_seconds=30,
                max_output_bytes=64 * 1024 + 1,
                surface="grabowski_terminal_run",
            )
        self.assertEqual(raised.exception.receipt["required_route"], "split_read")
        self.assertIn(
            "output_exceeds_synchronous_transport_ceiling",
            raised.exception.receipt["reason_codes"],
        )

    def test_terminal_run_uses_server_owned_limits(self) -> None:
        operator = _load_operator_module()
        parameters = inspect.signature(operator.grabowski_terminal_run).parameters
        self.assertEqual(list(parameters), ["argv", "cwd"])
        self.assertEqual(operator.grabowski_terminal_run.__defaults__, (None,))
        with patch.object(operator, "_require_operator_mutation") as require, patch.object(
            operator, "_run", return_value={"returncode": 0}
        ) as run:
            result = operator.grabowski_terminal_run(["printf", "ok"])
        require.assert_called_once_with(
            "terminal_execute",
            path=str(operator.HOME),
            opaque_command=True,
        )
        self.assertEqual(run.call_args.kwargs["timeout_seconds"], 30)
        self.assertEqual(run.call_args.kwargs["max_output_bytes"], 64 * 1024)
        contract = result["synchronous_contract"]
        self.assertTrue(contract["server_owned_limits"])
        self.assertFalse(contract["client_selected_timeout_supported"])
        self.assertFalse(contract["client_selected_output_limit_supported"])

    def test_terminal_run_gate_prevents_process_start(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator, "_run") as run:
            with self.assertRaises(operator.SynchronousCallShapeDenied):
                operator.grabowski_terminal_run(["bash", "-lc", "printf ok"])
        run.assert_not_called()

    def test_timeout_kills_the_full_process_group(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("start_new_session=True", source)
        self.assertIn("os.killpg(process.pid, signal.SIGTERM)", source)
        self.assertIn("os.killpg(process.pid, signal.SIGKILL)", source)

    def test_http_transport_is_loopback_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('choices=("stdio", "streamable-http")', source)
        self.assertIn('args.host != "127.0.0.1"', source)
        self.assertIn('mcp.run(transport=args.transport)', source)

    def test_background_jobs_have_a_separate_runtime_budget(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("DEFAULT_JOB_RUNTIME = 21_600", source)
        self.assertIn("MAX_JOB_RUNTIME = 86_400", source)
        self.assertIn("--property=RuntimeMaxSec=", source)

    def test_background_job_evidence_is_persistent(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn('JOBS_DIR = STATE_DIR / "jobs"', source)
        self.assertIn('directory / "metadata.json"', source)
        self.assertIn("--property=KillMode=control-group", source)
        self.assertIn("--property=StandardOutput=append:", source)
        self.assertIn("--property=StandardError=append:", source)
        self.assertIn("--description=", source)
        self.assertIn('"job_id"', source)
        self.assertIn('"expected_receipt"', source)
        self.assertIn('"terminalization_evidence"', source)
        self.assertIn('"notify_on_done"', source)

    def test_job_start_records_identity_receipt_and_no_default_notify(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="deadbeefcafe1234")
            command = [
                "python3",
                "-c",
                "print(\"${cluster}|$HOME|$(uname)|${{ github.sha }}|Grüße 🌍\")",
                "heredoc=<<EOF\n${expected}\nEOF",
            ]
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            managed_runtime = {
                "XDG_RUNTIME_DIR": "/run/user/1000",
                "HEIM_NODE_RUNTIME_ENV_DIR": "/run/user/1000/grabowski-node-runtime-env",
                "UV_CACHE_DIR": "/run/user/1000/grabowski-uv-cache",
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_managed_runtime_environment", return_value=managed_runtime
            ), patch.object(
                operator, "_run", return_value=launcher
            ) as run:
                job = operator.grabowski_job_start(command, cwd=str(cwd), runtime_seconds=60)

            self.assertEqual(job["job_id"], "deadbeefcafe")
            self.assertEqual(job["unit"], "grabowski-job-deadbeefcafe")
            self.assertTrue(job["owner"].startswith("uid:"))
            self.assertEqual(job["scope"]["cwd"], str(cwd.resolve()))
            self.assertEqual(job["scope"]["runtime_seconds"], 60)
            self.assertIn("started_at", job)
            self.assertTrue(job["started_at"].endswith("Z"))
            self.assertEqual(job["started_at_unix"], job["created_at_unix"])
            self.assertEqual(job["expected_receipt"]["status_tool"], "grabowski_job_status")
            self.assertEqual(job["expected_receipt"]["logs_tool"], "grabowski_job_logs")
            self.assertEqual(job["final_status"], "launch_submitted")
            self.assertEqual(job["terminalization_evidence"]["final_status"], "launch_submitted")
            self.assertEqual(job["terminalization_evidence"]["source"], "systemd-run-launch")
            self.assertEqual(job["launcher_evidence"]["returncode"], 0)
            self.assertEqual(job["notification_evidence"]["final_status_preserved"], "launch_submitted")
            self.assertIn("receipt_exists", job["expected_receipt"]["does_not_establish"])
            self.assertIn("job_success", job["expected_receipt"]["does_not_establish"])
            self.assertFalse(job["notify_on_done"]["requested"])
            self.assertFalse(job["notify_on_done"]["delivery_enabled"])
            self.assertEqual(job["notify_on_done"]["delivery_mode"], "none")
            self.assertEqual(job["notification_evidence"]["delivery_state"], "not_requested")
            persisted = json.loads(Path(job["metadata_path"]).read_text(encoding="utf-8"))
            self.assertEqual(persisted["final_status"], "launch_submitted")
            self.assertEqual(persisted["terminalization_evidence"]["source"], "systemd-run-launch")
            contract = persisted["finalization_contract"]
            self.assertEqual(contract["kind"], operator.GENERIC_JOB_FINALIZATION_KIND)
            self.assertEqual(
                persisted["expected_receipt"]["finalization_path"],
                str(jobs / job["unit"] / "finalization.json"),
            )
            self.assertEqual(
                contract["contract_sha256"],
                operator._json_sha256(
                    {key: value for key, value in contract.items() if key != "contract_sha256"}
                ),
            )
            invoked = run.call_args_list[0].args[0]
            separator = invoked.index("--")
            self.assertEqual(job["argv"], command)
            self.assertEqual(job["argv_sha256"], operator._argv_hash(command))
            self.assertEqual(invoked[separator + 1 :], operator.command_identity.systemd_escape_argv(command))
            self.assertNotIn("--expand-environment=no", invoked[:separator])
            self.assertIn("systemd-run", invoked)
            self.assertEqual(invoked.count("--property=LimitCORE=0"), 1)
            self.assertNotIn("--property=LimitNOFILE=65536", invoked)
            self.assertNotIn("--property=UMask=0077", invoked)
            self.assertTrue(any(item.startswith("--setenv=GRABOWSKI_JOB_ORIGIN_SHA256=") for item in invoked))
            self.assertIn("--setenv=GRABOWSKI_JOB_INVOKER_TOOL=grabowski_job_start", invoked)
            self.assertIn("--setenv=XDG_RUNTIME_DIR=/run/user/1000", invoked)
            self.assertIn(
                "--setenv=HEIM_NODE_RUNTIME_ENV_DIR=/run/user/1000/grabowski-node-runtime-env",
                invoked,
            )
            self.assertIn(
                "--setenv=UV_CACHE_DIR=/run/user/1000/grabowski-uv-cache",
                invoked,
            )
            self.assertTrue(any(" -I -m grabowski_job_finalizer" in item for item in invoked))
            self.assertEqual(job["schema_version"], 2)
            self.assertEqual(job["origin"]["invoker_tool"], "grabowski_job_start")
            self.assertEqual(job["origin_sha256"], persisted["origin_sha256"])
            self.assertNotIn("mail", invoked)
            self.assertNotIn("notify-send", invoked)

    def test_job_start_origin_binds_decision_review_registration(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            locks = state / "decision-review-locks"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="a11ce0000000ffffffffffffffffffff")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            decision_binding = {
                "schema_version": 1,
                "kind": operator.decision_reviews.BINDING_KIND,
                "repo": "Heimgewebe/Vibe-Lab",
                "pr": 350,
                "head_sha": "a" * 40,
                "base_sha": "b" * 40,
                "diff_sha256": "c" * 64,
                "slot": "Reviewer-A",
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(
                operator.decision_reviews, "LOCKS_ROOT", locks
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "print('review')"],
                    cwd=str(cwd),
                    runtime_seconds=60,
                    decision_review_binding=decision_binding,
                )

            expected = operator.decision_reviews.normalize_binding(decision_binding)
            self.assertEqual(job["scope"]["decision_bound_review"], expected)
            self.assertEqual(job["origin"]["scope"]["decision_bound_review"], expected)
            self.assertEqual(
                job["decision_review_contract"]["prefix"],
                operator.decision_reviews.RESULT_PREFIX,
            )
            self.assertEqual(
                job["decision_review_contract"]["required_result"]["slot"],
                "reviewer-a",
            )
            persisted = json.loads(Path(job["metadata_path"]).read_text(encoding="utf-8"))
            self.assertEqual(
                persisted["origin"]["scope"]["decision_bound_review"], expected
            )

    def test_broad_github_wrapper_blocks_merge_bypass_paths(self) -> None:
        operator = _load_operator_module()
        self.assertEqual(
            operator.merge_authority.github_merge_bypass_reason(["pr", "merge", "350"]),
            "direct_pr_merge",
        )
        self.assertEqual(
            operator.merge_authority.github_merge_bypass_reason(
                ["-R", "heimgewebe/vibe-lab", "pr", "merge", "350"]
            ),
            "direct_pr_merge",
        )
        self.assertEqual(
            operator.merge_authority.github_merge_bypass_reason(
                ["api", "--method", "PUT", "repos/heimgewebe/vibe-lab/pulls/350/merge"]
            ),
            "rest_pull_merge",
        )
        self.assertEqual(
            operator.merge_authority.github_merge_bypass_reason(
                ["api", "graphql", "-f", "query=mutation { mergePullRequest(input:{}) { clientMutationId } }"]
            ),
            "graphql_pull_merge",
        )
        self.assertIsNone(
            operator.merge_authority.github_merge_bypass_reason(
                ["pr", "view", "350", "--repo", "heimgewebe/vibe-lab"]
            )
        )
        with patch.object(operator, "_run") as run:
            with self.assertRaisesRegex(PermissionError, "Captain pr-merge"):
                operator.grabowski_github(["pr", "merge", "350"], cwd=str(ROOT))
            with self.assertRaisesRegex(PermissionError, "Captain pr-merge"):
                operator.grabowski_terminal_run(["gh", "pr", "merge", "350"], cwd=str(ROOT))
            with self.assertRaisesRegex(PermissionError, "Captain pr-merge"):
                operator.grabowski_job_start(["gh", "pr", "merge", "350"], cwd=str(ROOT))
        run.assert_not_called()

    def test_job_final_status_classification_is_explicit(self) -> None:
        operator = _load_operator_module()

        self.assertEqual(operator._job_final_status(False, {}), "missing_finalization_evidence")
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "active", "Result": "success", "ExecMainStatus": "0"}),
            "running",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "inactive", "Result": "success", "ExecMainStatus": "0"}),
            "succeeded",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "inactive", "Result": "exit-code", "ExecMainStatus": "1"}),
            "failed",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "failed", "Result": "exit-code", "ExecMainStatus": "0"}),
            "succeeded",
        )
        postflight = operator._job_terminalization_evidence(
            True,
            {
                "LoadState": "loaded",
                "ActiveState": "failed",
                "SubState": "failed",
                "Result": "exit-code",
                "ExecMainCode": "1",
                "ExecMainStatus": "0",
            },
        )
        self.assertEqual(postflight["final_status"], "succeeded")
        self.assertEqual(postflight["postflight_evidence"]["state"], "failed")
        self.assertEqual(
            postflight["postflight_evidence"]["primary_job_status_preserved"],
            "succeeded",
        )
        self.assertEqual(
            operator._job_final_status(True, {"ActiveState": "inactive", "Result": "", "ExecMainStatus": ""}),
            "terminated_unclear",
        )

    def test_launch_failure_persists_failed_evidence_not_started(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="bad1a0c00000ffffffffffffffffffff")
            launcher = {
                "returncode": 1,
                "stdout": "",
                "stderr": "systemd refused launch",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            launch_readback = {
                "returncode": 0,
                "stdout": "LoadState=not-found\nActiveState=inactive\n",
                "stderr": "",
                "timed_out": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", side_effect=[launcher, launch_readback]
            ):
                with self.assertRaisesRegex(RuntimeError, "systemd refused launch"):
                    operator.grabowski_job_start(["python3", "-c", "print(1)"], cwd=str(cwd))

            metadata_path = jobs / "grabowski-job-bad1a0c00000" / "metadata.json"
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["final_status"], "launch_failed")
            self.assertEqual(metadata["terminalization_evidence"]["source"], "systemd-run-launch")
            self.assertEqual(metadata["terminalization_evidence"]["final_status"], "launch_failed")
            self.assertFalse(metadata["terminalization_evidence"]["systemd_visible"])
            self.assertEqual(metadata["launcher_evidence"]["returncode"], 1)
            self.assertEqual(metadata["dispatch_outcome"], "not_started")
            self.assertEqual(metadata["dispatch_readback"]["outcome"], "not_started")
            self.assertNotEqual(metadata["final_status"], "started")

            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=\nExecMainCode=\nExecMainStatus=\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status("grabowski-job-bad1a0c00000")

            self.assertFalse(status["systemd_visible"])
            self.assertEqual(status["final_status"], "launch_failed")
            self.assertEqual(status["terminalization_evidence"]["source"], "systemd-run-launch")
            self.assertEqual(status["notification_evidence"]["final_status_preserved"], "launch_failed")

    def test_launcher_error_with_started_readback_is_a_started_job(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="feedface0000ffffffffffffffffffff")
            launcher = {
                "returncode": 1, "stdout": "", "stderr": "launcher lost reply",
                "argv": [], "argv_sha256": "0" * 64, "command": "systemd-run",
                "cwd": str(root), "timed_out": True, "duration_seconds": 60.0,
                "stdout_truncated": False, "stderr_truncated": False,
            }
            readback = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=active\n",
                "stderr": "",
                "timed_out": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", side_effect=[launcher, readback]
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "print(1)"], cwd=str(cwd)
                )

            self.assertEqual(job["dispatch_outcome"], "started")
            self.assertEqual(job["dispatch_readback"]["outcome"], "started")
            self.assertEqual(job["final_status"], "launch_submitted")
            self.assertEqual(
                job["terminalization_evidence"]["source"],
                "systemd-readback-after-launcher-error",
            )
            self.assertTrue(job["post_dispatch_warnings"])

    def test_launcher_error_with_unresolved_readback_is_outcome_unknown(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="decafbad0000ffffffffffffffffffff")
            launcher = {
                "returncode": 1, "stdout": "", "stderr": "launcher timed out",
                "argv": [], "argv_sha256": "0" * 64, "command": "systemd-run",
                "cwd": str(root), "timed_out": True, "duration_seconds": 60.0,
                "stdout_truncated": False, "stderr_truncated": False,
            }
            readback = {
                "returncode": 1, "stdout": "", "stderr": "dbus unavailable",
                "timed_out": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", side_effect=[launcher, readback]
            ):
                with self.assertRaises(operator.JobDispatchUnknown) as raised:
                    operator.grabowski_job_start(
                        ["python3", "-c", "print(1)"], cwd=str(cwd)
                    )

            self.assertEqual(raised.exception.dispatch_outcome, "outcome_unknown")
            metadata = json.loads(
                (jobs / "grabowski-job-decafbad0000" / "metadata.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(metadata["dispatch_outcome"], "outcome_unknown")
            self.assertEqual(metadata["final_status"], "launch_outcome_unknown")
            self.assertIsNone(operator._metadata_launch_failure_evidence(metadata))

    def test_metadata_failure_after_successful_dispatch_is_warning_not_failure(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="cab005e00000ffffffffffffffffffff")
            launcher = {
                "returncode": 0, "stdout": "started", "stderr": "",
                "argv": [], "argv_sha256": "0" * 64, "command": "systemd-run",
                "cwd": str(root), "timed_out": False, "duration_seconds": 0.01,
                "stdout_truncated": False, "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ), patch.object(
                operator, "_replace_job_metadata", side_effect=OSError("disk full")
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "print(1)"], cwd=str(cwd)
                )

            self.assertEqual(job["dispatch_outcome"], "started")
            self.assertIsNone(job["metadata_path"])
            self.assertTrue(job["post_dispatch_warnings"])
            self.assertIn("metadata persist failed", job["post_dispatch_warnings"][0])

    def test_not_found_systemd_unit_has_valid_query_but_missing_finalization(self) -> None:
        operator = _load_operator_module()
        result = {"returncode": 0}
        properties = {"LoadState": "not-found", "ActiveState": "inactive"}

        self.assertTrue(operator._systemd_job_query_valid(result, properties))
        self.assertFalse(operator._systemd_job_query_visible(result, properties))
        evidence = operator._job_terminalization_evidence(False, properties, query_valid=True)
        self.assertTrue(evidence["query_valid"])
        self.assertFalse(evidence["systemd_visible"])
        self.assertEqual(evidence["final_status"], "missing_finalization_evidence")

    def test_malformed_systemd_show_is_missing_finalization_evidence(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="e0005a0c0000ffffffffffffffffffff")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(["python3", "-c", "print(1)"], cwd=str(cwd))

            systemctl = {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(job["unit"])

            self.assertFalse(status["systemd_visible"])
            self.assertEqual(status["final_status"], "missing_finalization_evidence")
            self.assertFalse(status["terminalization_evidence"]["query_valid"])

    def test_notify_on_done_metadata_does_not_hide_failed_finalization(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="feedfacecafe9999")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "raise SystemExit(1)"],
                    cwd=str(cwd),
                    runtime_seconds=60,
                    notify_on_done={"requested": True, "channels": ["chat"], "note": "done"},
                )

            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nRuntimeMaxUSec=60000000\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(job["unit"])

            self.assertEqual(status["final_status"], "failed")
            self.assertEqual(status["job_record"]["final_status"], "failed")
            self.assertTrue(status["job_record"]["notify_on_done"]["requested"])
            self.assertEqual(status["job_record"]["notify_on_done"]["channels"], ["chat"])
            self.assertTrue(status["notification_evidence"]["delivery_enabled"])
            self.assertEqual(status["notification_evidence"]["delivery_state"], "missing_receipt")
            self.assertEqual(status["notification_evidence"]["final_status_preserved"], "failed")
            self.assertIn("hidden_finalization_failure", status["terminalization_evidence"]["does_not_establish"])

    def test_notify_on_done_metadata_is_strict_and_bounded(self) -> None:
        operator = _load_operator_module()
        self.assertEqual(operator._normalize_notify_on_done(None)["requested"], False)
        self.assertEqual(operator._normalize_notify_on_done({})["requested"], False)
        self.assertEqual(operator._normalize_notify_on_done({"requested": True})["requested"], True)
        with self.assertRaisesRegex(ValueError, "Unknown notify_on_done"):
            operator._normalize_notify_on_done({"requested": True, "send": True})
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            operator._normalize_notify_on_done({"requested": "yes"})
        with self.assertRaisesRegex(ValueError, "control characters"):
            operator._normalize_notify_on_done({"requested": True, "channels": ["bad\nchannel"]})
        with self.assertRaisesRegex(ValueError, "control characters"):
            operator._normalize_notify_on_done({"requested": True, "note": "done\n"})

    def test_legacy_metadata_is_projected_for_status_and_logs(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            unit = "grabowski-job-legacy000001"
            directory = jobs / unit
            directory.mkdir(parents=True)
            stdout_path = directory / "stdout.log"
            stderr_path = directory / "stderr.log"
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            metadata = {
                "schema_version": 1,
                "unit": unit,
                "argv": ["python3"],
                "argv_sha256": "a" * 64,
                "command": "python3",
                "cwd": str(root),
                "runtime_seconds": 60,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            }
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(unit)
            with patch.object(operator, "STATE_DIR", state), patch.object(operator, "JOBS_DIR", jobs):
                logs = operator.grabowski_job_logs(unit, max_lines=5)

            self.assertEqual(status["job_record"]["job_id"], "legacy000001")
            self.assertTrue(status["job_record"]["owner"].startswith("uid:"))
            self.assertEqual(status["job_record"]["scope"]["argv_sha256"], "a" * 64)
            self.assertEqual(status["job_record"]["expected_receipt"]["status_tool"], "grabowski_job_status")
            self.assertFalse(status["job_record"]["notify_on_done"]["requested"])
            self.assertTrue(status["job_record"]["metadata_projection"]["legacy_fields_projected"])
            self.assertEqual(logs["job_identity"]["job_id"], "legacy000001")
            self.assertEqual(logs["expected_receipt"]["logs_tool"], "grabowski_job_logs")
            self.assertFalse(logs["notify_on_done"]["requested"])

    def test_invalid_stored_notify_metadata_degrades_without_delivery(self) -> None:
        operator = _load_operator_module()
        metadata = {
            "schema_version": 1,
            "unit": "grabowski-job-invalidnotify",
            "notify_on_done": {"requested": "yes"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            directory = jobs / metadata["unit"]
            directory.mkdir(parents=True)
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            (directory / "stdout.log").write_text("", encoding="utf-8")
            (directory / "stderr.log").write_text("", encoding="utf-8")
            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(metadata["unit"])

            notify = status["job_record"]["notify_on_done"]
            self.assertFalse(notify["requested"])
            self.assertTrue(notify["metadata_invalid"])
            self.assertFalse(status["notification_evidence"]["delivery_enabled"])
            self.assertEqual(status["notification_evidence"]["delivery_state"], "not_requested")

            metadata["notify_on_done"] = {"requested": True, "send": True}
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(metadata["unit"])

            notify = status["job_record"]["notify_on_done"]
            self.assertFalse(notify["requested"])
            self.assertTrue(notify["metadata_invalid"])
            self.assertIn("Unknown notify_on_done field", notify["metadata_error"])
            self.assertFalse(status["notification_evidence"]["delivery_enabled"])

            for invalid_notify, expected_error in (
                ({"requested": True, "delivery_enabled": False}, "delivery_enabled is invalid"),
                ({"requested": True, "delivery_mode": "real_delivery"}, "delivery_mode is invalid"),
                ({"requested": True, "does_not_establish": ["job_success"]}, "does_not_establish is invalid"),
            ):
                metadata["notify_on_done"] = invalid_notify
                (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
                with patch.object(operator, "STATE_DIR", state), patch.object(
                    operator, "JOBS_DIR", jobs
                ), patch.object(operator, "_run", return_value=systemctl):
                    status = operator.grabowski_job_status(metadata["unit"])

                notify = status["job_record"]["notify_on_done"]
                self.assertFalse(notify["requested"])
                self.assertTrue(notify["metadata_invalid"])
                self.assertIn(expected_error, notify["metadata_error"])
                self.assertFalse(status["notification_evidence"]["delivery_enabled"])

            metadata["notify_on_done"] = {"requested": True, "send\nnow": True}
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(metadata["unit"])
            self.assertIn("�", status["job_record"]["notify_on_done"]["metadata_error"])

    def test_job_metadata_projection_marks_identity_mismatch(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            unit = "grabowski-job-realjobid001"
            directory = jobs / unit
            directory.mkdir(parents=True)
            (directory / "stdout.log").write_text("", encoding="utf-8")
            (directory / "stderr.log").write_text("", encoding="utf-8")
            metadata = {
                "schema_version": 1,
                "unit": unit,
                "job_id": "wrongjobid",
                "stdout_path": str(directory / "stdout.log"),
                "stderr_path": str(directory / "stderr.log"),
            }
            (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
            systemctl = {
                "returncode": 0,
                "stdout": "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\nExecMainCode=0\nExecMainStatus=0\n",
                "stderr": "",
                "argv": [],
                "argv_sha256": "1" * 64,
                "command": "systemctl show",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator, "_run", return_value=systemctl):
                status = operator.grabowski_job_status(unit)

            self.assertEqual(status["job_record"]["job_id"], "realjobid001")
            projection = status["job_record"]["metadata_projection"]
            self.assertTrue(projection["job_id_projected"])
            self.assertTrue(projection["stored_job_id_mismatch"])

    def test_replace_job_metadata_uses_unique_temp_and_cleans_failed_write(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            first = {"unit": "grabowski-job-temp000000", "n": 1}
            second = {"unit": "grabowski-job-temp000000", "n": 2}
            broken = {"unit": "grabowski-job-temp000000", "n": 3}
            operator._replace_job_metadata(directory, first)
            operator._replace_job_metadata(directory, second)
            self.assertEqual(json.loads((directory / "metadata.json").read_text(encoding="utf-8"))["n"], 2)
            self.assertEqual(list(directory.glob("metadata.json.*.tmp")), [])

            with patch.object(operator.os, "write", side_effect=RuntimeError("write failed")):
                with self.assertRaisesRegex(RuntimeError, "write failed"):
                    operator._replace_job_metadata(directory, broken)
            self.assertEqual(json.loads((directory / "metadata.json").read_text(encoding="utf-8"))["n"], 2)
            self.assertEqual(list(directory.glob("metadata.json.*.tmp")), [])

    def test_job_logs_expose_identity_receipt_and_notify_metadata(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            jobs = state / "jobs"
            cwd = root / "cwd"
            cwd.mkdir(parents=True)
            fake_uuid = types.SimpleNamespace(hex="abc123abc123ffff")
            launcher = {
                "returncode": 0,
                "stdout": "started",
                "stderr": "",
                "argv": [],
                "argv_sha256": "0" * 64,
                "command": "systemd-run",
                "cwd": str(root),
                "timed_out": False,
                "duration_seconds": 0.01,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
            with patch.object(operator, "STATE_DIR", state), patch.object(
                operator, "JOBS_DIR", jobs
            ), patch.object(operator.uuid, "uuid4", return_value=fake_uuid), patch.object(
                operator, "_run", return_value=launcher
            ):
                job = operator.grabowski_job_start(
                    ["python3", "-c", "print(1)"],
                    cwd=str(cwd),
                    notify_on_done={"requested": True, "channels": ["chat"]},
                )
            with patch.object(operator, "STATE_DIR", state), patch.object(operator, "JOBS_DIR", jobs):
                logs = operator.grabowski_job_logs(job["unit"], max_lines=5)

            self.assertEqual(logs["job_identity"]["job_id"], "abc123abc123")
            self.assertEqual(logs["expected_receipt"]["metadata_path"], job["metadata_path"])
            self.assertTrue(logs["notify_on_done"]["requested"])
            self.assertEqual(logs["stdout"]["text"], "")
            self.assertEqual(logs["stderr"]["text"], "")

    def test_systemd_description_is_bounded_single_line_metadata(self) -> None:
        operator = _load_operator_module()
        digest = "a" * 64

        description = operator._systemd_safe_description(
            "job",
            "grabowski-job-deadbeefcafe.service",
            digest,
        )

        self.assertEqual(
            "Grabowski job grabowski-job-deadbeefcafe.service argv=aaaaaaaaaaaa",
            description,
        )
        self.assertNotIn("\n", description)
        self.assertNotIn("\r", description)
        self.assertLessEqual(len(description.encode("utf-8")), 200)

    def test_systemd_description_rejects_payload_like_values(self) -> None:
        operator = _load_operator_module()
        with self.assertRaises(ValueError):
            operator._systemd_safe_description("job\n[Service]", "grabowski-job-x.service")
        with self.assertRaises(ValueError):
            operator._systemd_safe_description("job", "grabowski-job-x.service\n[Service]")
        with self.assertRaises(ValueError):
            operator._systemd_safe_description("job", "grabowski-job-x.service", "bad")

    def test_secret_bearing_argv_is_redacted_in_results(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("def _redact_argv", source)
        self.assertIn('"argv_sha256"', source)
        self.assertIn("_redacted_command", source)

    def test_operator_mutations_have_capability_and_kill_switch_gate(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("OPERATOR_CAPABILITIES", source)
        self.assertIn("def _require_operator_mutation", source)
        self.assertIn("base._require_blockade_allows_mutation(", source)
        self.assertIn("base._require_valid_audit_chain()", source)

    def test_operator_mutations_require_valid_audit_chain(self) -> None:
        operator = _load_operator_module()
        with patch.object(
            operator.base,
            "_require_valid_audit_chain",
            side_effect=RuntimeError("Audit log verification failed: bad-chain"),
        ):
            with self.assertRaisesRegex(RuntimeError, "bad-chain"):
                operator._require_operator_mutation("git_cli")

    def test_operator_mutation_gate_uses_operator_capabilities_only(self) -> None:
        operator_capabilities = _load_operator_module().OPERATOR_CAPABILITIES
        allowed = set(operator_capabilities)
        violations: list[str] = []

        for path in sorted((ROOT / "src").glob("grabowski*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                function = node.func
                is_operator_gate = (
                    isinstance(function, ast.Attribute)
                    and function.attr == "_require_operator_mutation"
                ) or (
                    isinstance(function, ast.Name)
                    and function.id == "_require_operator_mutation"
                )
                if not is_operator_gate:
                    continue
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: non-literal capability")
                    continue
                capability = node.args[0].value
                if not isinstance(capability, str):
                    violations.append(f"{path.relative_to(ROOT)}:{node.lineno}: non-string capability")
                    continue
                if capability not in allowed:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno}: {capability} is not an operator capability"
                    )

        self.assertEqual([], violations)

    def test_privileged_action_tool_is_reference_only(self) -> None:
        source = SOURCE.read_text(encoding="utf-8")
        self.assertIn("PRIVILEGED_REFERENCE_ACTIONS", source)
        self.assertIn('"unprivileged-reference-only"', source)
        self.assertIn('"may_execute": False', source)
        self.assertIn('"requires_external_privileged_agent": True', source)
        self.assertIn('"expires_at_unix"', source)
        self.assertIn('"replay_policy"', source)

    def test_secret_argv_values_are_redacted_from_command_output(self) -> None:
        operator = _load_operator_module()
        secret = "plain-secret-value-12345"
        script = (
            "import sys; "
            "print(sys.argv[2]); "
            "print(sys.argv[2], file=sys.stderr)"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = operator._run(
                [sys.executable, "-c", script, "--token", secret],
                cwd=Path(directory),
                timeout_seconds=30,
                max_output_bytes=10000,
            )
        self.assertEqual(result["returncode"], 0)
        self.assertNotIn(secret, result["argv"])
        self.assertNotIn(secret, result["command"])
        self.assertNotIn(secret, result["stdout"])
        self.assertNotIn(secret, result["stderr"])
        self.assertIn("<REDACTED>", result["stdout"])
        self.assertIn("<REDACTED>", result["stderr"])

    def test_short_secret_values_do_not_corrupt_diagnostic_output(self) -> None:
        operator = _load_operator_module()
        script = "print('status=true count=1 build=101 feature=false')"
        with tempfile.TemporaryDirectory() as directory:
            result = operator._run(
                [sys.executable, "-c", script, "--token", "true"],
                cwd=Path(directory),
                timeout_seconds=30,
                max_output_bytes=10000,
            )
        self.assertEqual(
            result["stdout"],
            "status=true count=1 build=101 feature=false\n",
        )

    def test_short_secret_value_is_redacted_when_emitted_as_complete_line(self) -> None:
        operator = _load_operator_module()
        script = "import sys; print(sys.argv[2])"
        with tempfile.TemporaryDirectory() as directory:
            result = operator._run(
                [sys.executable, "-c", script, "--token", "1"],
                cwd=Path(directory),
                timeout_seconds=30,
                max_output_bytes=10000,
            )
        self.assertEqual(result["stdout"], "<REDACTED>\n")

    def test_short_secret_value_is_redacted_in_named_context(self) -> None:
        operator = _load_operator_module()
        self.assertEqual(
            operator._redact("token: 1 status=101", ["1"]),
            "token: <REDACTED> status=101",
        )

    def test_validate_argv_uses_forbidden_host_guard_fail_closed(self) -> None:
        operator = _load_operator_module()
        observed: list[list[str]] = []

        def reject(argv: list[str], *, policy=None) -> None:
            observed.append([*argv, f"policy={policy['active_profile']}"])
            if "blocked.example" in argv:
                raise PermissionError("Forbidden host in command arguments: blocked.example")

        operator.base._reject_forbidden_hosts_in_argv = reject
        self.assertEqual(operator._validate_argv(["echo", "ok"]), ["echo", "ok"])
        self.assertEqual(observed, [["echo", "ok", "policy=operator"]])
        with self.assertRaisesRegex(PermissionError, "blocked.example"):
            operator._validate_argv(["ssh", "blocked.example"])

        delattr(operator.base, "_reject_forbidden_hosts_in_argv")
        with self.assertRaises(AttributeError):
            operator._validate_argv(["echo", "unguarded"])

    def test_explicit_direct_command_arguments_cannot_target_canonical_blockade_marker(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "state" / "operator-kill-switch"
            marker.parent.mkdir()
            with (
                patch.object(operator, "HOME", root),
                patch.object(operator.base, "KILL_SWITCH_PATH", marker),
                patch.object(
                    operator.base,
                    "_trusted_owner_enabled",
                    return_value=True,
                    create=True,
                ),
                patch.dict("os.environ", {"HOME": str(root)}),
            ):
                blocked = (
                    ["touch", str(marker)],
                    ["tool", f"--output={marker}"],
                    ["python3", "-c", f"open({str(marker)!r}, 'w').close()"],
                    ["sh", "-c", "touch $HOME/state/operator-kill-switch"],
                    ["touch", "state/operator-kill-switch"],
                )
                for argv in blocked:
                    with self.subTest(argv=argv):
                        with self.assertRaisesRegex(
                            PermissionError, "typed blockade lifecycle"
                        ):
                            operator._validate_argv(argv, cwd=root)

                self.assertEqual(
                    operator._validate_argv(
                        ["touch", "state/operator-kill-switch-note"], cwd=root
                    ),
                    ["touch", "state/operator-kill-switch-note"],
                )

    def test_relative_command_arguments_may_not_target_merges(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "repos" / "merges"
            evidence.mkdir(parents=True)
            with patch.object(operator, "EVIDENCE_ROOT", evidence):
                with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                    operator._validate_argv(
                        ["touch", "repos/merges/proof.txt"],
                        cwd=root,
                    )
                with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                    operator._validate_argv(
                        ["tool", "--output=repos/merges/proof.txt"],
                        cwd=root,
                    )

    def test_shell_command_fragments_may_not_target_merges(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "repos" / "merges"
            evidence.mkdir(parents=True)
            with (
                patch.object(operator, "HOME", root),
                patch.object(operator, "EVIDENCE_ROOT", evidence),
                patch.dict("os.environ", {"HOME": str(root)}),
            ):
                for argv in (
                    ["sh", "-c", "touch ~/repos/merges/proof.txt"],
                    ["sh", "-c", "touch $HOME/repos/merges/proof.txt"],
                    ["sh", "-c", "touch ${HOME}/repos/merges/proof.txt"],
                    ["tool", "--output=$HOME/repos/merges/proof.txt"],
                ):
                    with self.subTest(argv=argv):
                        with self.assertRaisesRegex(PermissionError, "immutable evidence"):
                            operator._validate_argv(argv, cwd=root)

    def test_push_force_delete_aggregate_and_indirect_options_are_blocked(self) -> None:
        operator = _load_operator_module()
        blocked = (
            ["push", "--force", "origin", "HEAD:refs/heads/feature"],
            ["push", "--force-with-lease", "origin", "HEAD:refs/heads/feature"],
            ["push", "--force-with-lease=feature", "origin", "HEAD:refs/heads/feature"],
            ["push", "--force-if-includes", "origin", "HEAD:refs/heads/feature"],
            ["push", "-fu", "origin", "HEAD:refs/heads/feature"],
            ["push", "origin", "+HEAD:refs/heads/feature"],
            ["push", "--delete", "origin", "feature"],
            ["push", "--delete=feature", "origin"],
            ["push", "-d", "origin", "feature"],
            ["push", "--prune", "origin", "HEAD:refs/heads/feature"],
            ["push", "--mirror", "origin"],
            ["push", "--all", "origin"],
            ["push", "--tags", "origin"],
            ["push", "--follow-tags", "origin", "HEAD:refs/heads/feature"],
            ["push", "--push-option=ci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "--push-option", "ci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "-o", "ci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "-oci.skip", "origin", "HEAD:refs/heads/feature"],
            ["push", "--receive-pack=git-receive-pack", "origin", "HEAD:refs/heads/feature"],
            ["push", "--exec", "git-receive-pack", "origin", "HEAD:refs/heads/feature"],
            ["push", "--recurse-submodules=on-demand", "origin", "HEAD:refs/heads/feature"],
            ["push", "--no-verify", "origin", "HEAD:refs/heads/feature"],
            ["push", "--repo=origin", "HEAD:refs/heads/feature"],
            ["push", "--for", "origin", "HEAD:refs/heads/feature"],
            ["push", "--mir", "origin"],
            ["push", "--del", "origin", "feature"],
            ["push", "--signed", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=true", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=false", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=if-asked", "origin", "HEAD:refs/heads/feature"],
            ["push", "--signed=always", "origin", "HEAD:refs/heads/feature"],
            ["push", "--atomic=true", "origin", "HEAD:refs/heads/feature"],
        )
        with patch.object(operator, "_git_config_entries", return_value=[]):
            for arguments in blocked:
                with self.subTest(arguments=arguments):
                    with self.assertRaises(PermissionError):
                        operator._guard_git(arguments, Path("/repo"))

    def test_push_requires_one_explicit_non_protected_branch_refspec(self) -> None:
        operator = _load_operator_module()
        blocked = (
            ["push"],
            ["push", "origin"],
            ["push", "origin", "feature"],
            ["push", "origin", "HEAD:feature"],
            ["push", "origin", "HEAD:refs/tags/feature"],
            ["push", "origin", "HEAD:refs/heads/main"],
            ["push", "origin", "HEAD:refs/heads/master"],
            ["push", "origin", ":refs/heads/feature"],
            ["push", "origin", "HEAD:"],
            ["push", "origin", "HEAD:refs/heads/*"],
            ["push", "origin", "HEAD:refs/heads/feature", "HEAD:refs/heads/other"],
            ["push", "origin", "HEAD:refs/heads/feature:refs/heads/other"],
            ["push", "https://example.invalid/repo.git", "HEAD:refs/heads/feature"],
            ["push", "origin", "HEAD:refs/heads/feature name"],
            ["push", "origin", "HEAD:refs/heads/.invalid"],
        )
        with patch.object(operator, "_git_config_entries", return_value=[]):
            for arguments in blocked:
                with self.subTest(arguments=arguments):
                    with self.assertRaises(PermissionError):
                        operator._guard_git(arguments, Path("/repo"))

    def test_push_guard_does_not_weaken_in_trusted_owner_mode(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator, "_trusted_owner_mode", return_value=True),
            patch.object(operator, "_git_config_entries", return_value=[]),
        ):
            for arguments in (
                ["push", "--force-with-lease", "origin", "HEAD:refs/heads/feature"],
                ["push", "origin", "HEAD:refs/heads/main"],
            ):
                with self.subTest(arguments=arguments):
                    with self.assertRaises(PermissionError):
                        operator._guard_git(arguments, Path("/repo"))

    def test_git_push_config_control_characters_are_rejected(self) -> None:
        operator = _load_operator_module()
        with self.assertRaisesRegex(ValueError, "control characters"):
            operator._guard_git(
                [
                    "-c",
                    "remote.origin.push=HEAD:refs/heads/feature\nalias.ship=!sh",
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                Path("/repo"),
            )

    def test_push_command_line_configuration_is_blocked_fail_closed(self) -> None:
        operator = _load_operator_module()
        with self.assertRaisesRegex(PermissionError, "configuration"):
            operator._guard_git(
                [
                    "-c",
                    "core.pager=cat",
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                Path("/repo"),
            )
        with self.assertRaises(PermissionError):
            operator._guard_git(
                [
                    "--config-env=remote.origin.push=FORCE_REFSPEC",
                    "push",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                Path("/repo"),
            )

    def test_repository_push_configuration_is_blocked_for_selected_remote(self) -> None:
        operator = _load_operator_module()
        configurations = (
            ("remote.origin.push", "HEAD:refs/heads/feature"),
            ("remote.origin.pushurl", "git@evil.invalid:other/repo.git"),
            ("remote.origin.mirror", "true"),
            ("remote.origin.receivepack", "git-receive-pack"),
            ("push.pushOption", "ci.skip"),
            ("push.followTags", "true"),
            ("push.gpgSign", "if-asked"),
            ("push.recurseSubmodules", "on-demand"),
        )
        for key, value in configurations:
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    repo = Path(directory)
                    operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
                    operator.subprocess.run(
                        ["git", "-C", str(repo), "config", key, value],
                        check=True,
                    )
                    with self.assertRaisesRegex(PermissionError, "configuration"):
                        operator._guard_git(
                            ["push", "origin", "HEAD:refs/heads/feature"],
                            repo,
                        )

    def test_unrelated_remote_configuration_does_not_block_explicit_safe_push(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "git@github.com:heimgewebe/grabowski.git"],
                check=True,
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "remote.backup.mirror", "true"],
                check=True,
            )
            operator._guard_git(
                ["push", "origin", "HEAD:refs/heads/feature"],
                repo,
            )

    def test_rewritten_or_multiple_remote_push_targets_are_blocked(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "ssh://safe.example/repo.git"],
                check=True,
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "url.ssh://redirect.example/.pushInsteadOf", "ssh://safe.example/"],
                check=True,
            )
            with self.assertRaisesRegex(PermissionError, "rewrite"):
                operator._guard_git(["push", "origin", "HEAD:refs/heads/feature"], repo)

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "ssh://one.example/repo.git"],
                check=True,
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "--add", "remote.origin.url", "ssh://two.example/repo.git"],
                check=True,
            )
            with self.assertRaisesRegex(PermissionError, "exactly one configured URL"):
                operator._guard_git(["push", "origin", "HEAD:refs/heads/feature"], repo)

    def test_identity_preserving_https_to_ssh_rewrite_is_allowed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/heimgewebe/grabowski.git",
                ],
                check=True,
            )
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "url.git@github.com:.pushInsteadOf",
                    "https://github.com/",
                ],
                check=True,
            )
            operator._guard_git(["push", "origin", "HEAD:refs/heads/feature"], repo)

    def test_ssh_user_change_and_url_parameters_are_blocked(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "remote",
                    "add",
                    "origin",
                    "git@github.com:heimgewebe/grabowski.git",
                ],
                check=True,
            )
            with patch.object(
                operator,
                "_git_config_values",
                return_value=["git@github.com:heimgewebe/grabowski.git"],
            ), patch.object(
                operator.subprocess,
                "run",
                return_value=types.SimpleNamespace(
                    returncode=0,
                    stdout="root@github.com:heimgewebe/grabowski.git\n",
                    stderr="",
                ),
            ):
                with self.assertRaisesRegex(PermissionError, "changes the selected push target"):
                    operator._validate_push_remote_target(repo, "origin")

        for url in (
            "ssh://git:secret@example.invalid/repo.git",
            "ssh://git@example.invalid/repo.git?command=other",
            "ssh://git@example.invalid/repo.git#fragment",
            "-oProxyCommand=evil:repo.git",
            "-oProxyCommand=evil@github.com:repo.git",
        ):
            with self.subTest(url=url):
                self.assertIsNone(operator._remote_target_identity(url))

    def test_https_target_without_ssh_resolution_is_blocked(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "remote",
                    "add",
                    "origin",
                    "https://example.invalid/heimgewebe/grabowski.git",
                ],
                check=True,
            )
            with self.assertRaisesRegex(PermissionError, "SSH remote target"):
                operator._guard_git(["push", "origin", "HEAD:refs/heads/feature"], repo)

    def test_git_repository_rebinding_and_alias_injection_are_blocked(self) -> None:
        operator = _load_operator_module()
        for arguments in (
            ["-C", "/tmp/other", "push", "origin", "HEAD:refs/heads/feature"],
            ["--git-dir=/tmp/other.git", "push", "origin", "HEAD:refs/heads/feature"],
            ["--work-tree", "/tmp/other", "status"],
            ["-c", "alias.ship=push origin HEAD:refs/heads/main", "ship"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(PermissionError):
                    operator._guard_git(arguments, Path("/repo"))

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "alias.ship",
                    "push origin HEAD:refs/heads/main",
                ],
                check=True,
            )
            with self.assertRaisesRegex(PermissionError, "Configured Git aliases"):
                operator._guard_git(["ship"], repo)

    def test_explicit_safe_feature_push_subset_is_allowed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "git@github.com:heimgewebe/grabowski.git"],
                check=True,
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "backup.with.dot", "git@github.com:heimgewebe/grabowski.git"],
                check=True,
            )
            for arguments in (
                ["push", "origin", "HEAD:refs/heads/feature"],
                [
                    "push",
                    "--dry-run",
                    "--porcelain",
                    "--atomic",
                    "--thin",
                    "--ipv4",
                    "--set-upstream",
                    "origin",
                    "HEAD:refs/heads/feature",
                ],
                ["push", "-nquv4", "origin", "HEAD:refs/heads/feature"],
                ["push", "--", "backup.with.dot", "HEAD:refs/heads/feature"],
            ):
                with self.subTest(arguments=arguments):
                    operator._guard_git(arguments, repo)

    def test_git_environment_strips_repository_and_config_injection(self) -> None:
        operator = _load_operator_module()
        injected = {
            "PATH": "/usr/bin",
            "SSH_AUTH_SOCK": "/run/user/1000/agent",
            "GIT_DIR": "/tmp/other.git",
            "GIT_WORK_TREE": "/tmp/other",
            "GIT_EXEC_PATH": "/tmp/git-tools",
            "GIT_CONFIG": "/tmp/gitconfig",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "remote.origin.push",
            "GIT_CONFIG_VALUE_0": "+HEAD:refs/heads/main",
        }
        with patch.object(operator, "_safe_environment", return_value=injected):
            environment = operator._git_environment()
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertEqual(environment["SSH_AUTH_SOCK"], "/run/user/1000/agent")
        for key in injected:
            if key.startswith("GIT_CONFIG_") or key in operator.GIT_ENVIRONMENT_EXACT_DENY:
                self.assertNotIn(key, environment)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GCM_INTERACTIVE"], "never")

    def test_prune_and_direct_remote_write_bypasses_are_blocked(self) -> None:
        operator = _load_operator_module()
        for arguments in (
            ["push", "--prune", "origin"],
            ["send-pack", "--force", "origin", "HEAD:main"],
            ["http-push", "--force", "origin", "HEAD:main"],
            ["subtree", "push", "--prefix", "docs", "origin", "pages"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(PermissionError):
                    operator._guard_git(arguments, Path("/repo"))

    def test_unclassified_local_git_mutators_are_blocked_fail_closed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for arguments in (
                ["fetch", "origin"],
                ["worktree", "add", "/tmp/other"],
                ["sparse-checkout", "init", "--cone"],
                ["bisect", "start"],
                ["clean", "-fd"],
                ["config", "core.filemode", "false"],
                ["hash-object", "-w", "README.md"],
            ):
                with self.subTest(arguments=arguments):
                    with self.assertRaisesRegex(
                        PermissionError, "Unclassified local Git subcommand"
                    ):
                        operator._guard_git(arguments, repo)

    def test_explicit_local_git_read_subset_remains_allowed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for arguments in (
                ["status", "--short"],
                ["diff", "--stat"],
                ["rev-parse", "--git-dir"],
                ["ls-files", "--stage"],
                ["log", "--oneline", "-1"],
            ):
                with self.subTest(arguments=arguments):
                    operator._guard_git(arguments, repo)

    def test_read_only_git_output_writes_are_blocked(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            output = str(repo / "command-output")
            for arguments in (
                ["diff", f"--output={output}"],
                ["diff", "--output", output],
                ["show", f"--output={output}"],
                ["log", "--output", output],
            ):
                with self.subTest(arguments=arguments):
                    with self.assertRaisesRegex(
                        PermissionError, "read-only-classified"
                    ):
                        operator._guard_git(arguments, repo)

    def test_git_stash_is_blocked_without_repository_scope_serialization(self) -> None:
        operator = _load_operator_module()
        for arguments in (
            ["stash"],
            ["stash", "push"],
            ["stash", "save"],
            ["stash", "apply"],
            ["stash", "pop"],
            ["stash", "store", "a" * 40],
            ["stash", "drop"],
            ["stash", "clear"],
            ["stash", "branch", "recovery"],
            ["stash", "create"],
            ["stash", "list"],
            ["stash", "show"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(PermissionError, "repository-wide"):
                    operator._guard_git(arguments, Path("/repo"))

    def test_git_environment_disables_optional_read_side_effects(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator, "_safe_environment", return_value={"PATH": "/usr/bin"}):
            environment = operator._git_environment()
        self.assertEqual("0", environment["GIT_OPTIONAL_LOCKS"])

    def test_grabowski_git_local_mutation_requires_branch_attempt(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_guard_git", return_value=None),
            ):
                with self.assertRaisesRegex(PermissionError, "requires a branch_attempt"):
                    operator.grabowski_git(str(repo), ["commit", "-m", "unsafe"])

    def test_grabowski_git_mv_requires_branch_attempt(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_guard_git", return_value=None),
            ):
                with self.assertRaisesRegex(PermissionError, "requires a branch_attempt"):
                    operator.grabowski_git(str(repo), ["mv", "old", "new"])

    def test_grabowski_git_pull_is_blocked_as_repository_wide_mutation(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            with patch.object(operator, "_require_operator_mutation", return_value=None):
                with self.assertRaisesRegex(PermissionError, "repository-wide"):
                    operator.grabowski_git(str(repo), ["pull", "--ff-only"])

    def test_grabowski_git_branch_attempt_blocks_other_branch_targets(self) -> None:
        operator = _load_operator_module()
        attempt = {
            "schema_version": 1,
            "owner_id": "operator:same-owner",
            "operation_id": "operation-a",
            "attempt_id": "attempt-1",
            "branch": "feature",
            "expected_preimage_sha256": "a" * 64,
        }
        for arguments in (
            ["update-ref", "refs/heads/other", "b" * 40],
            ["update-ref", "--stdin"],
            ["update-ref", "--no-deref", "HEAD", "b" * 40],
            ["branch", "-f", "other", "HEAD"],
            ["symbolic-ref", "HEAD", "refs/heads/other"],
            ["symbolic-ref", "--delete", "HEAD"],
            ["symbolic-ref", "-d", "HEAD"],
            ["checkout", "other"],
            ["checkout", "--detach", "HEAD"],
            ["checkout", "-d", "HEAD"],
            ["checkout", "-bother"],
            ["checkout", "-Bother"],
            ["checkout", "-qbother"],
            ["checkout", "--orphan=other"],
            ["checkout", "--conflict", "merge", "other"],
            ["switch", "other"],
            ["switch", "-c", "other"],
            ["switch", "-cother"],
            ["switch", "-Cother"],
            ["switch", "-qcother"],
            ["switch", "--create=other"],
            ["switch", "--force-create=other"],
            ["switch", "--conflict", "merge", "other"],
            ["switch", "--detach", "HEAD"],
            ["switch", "--detach=HEAD"],
            ["switch", "-d", "HEAD"],
            ["rebase", "main", "other"],
            ["rebase", "--continue"],
            ["reset", "--hard", "--recurse-submodules"],
            ["restore", "--recurse-submodules", "README.md"],
            ["update-index", "--assume-unchanged", "README.md"],
            ["update-index", "--skip-worktree", "README.md"],
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(
                    PermissionError, "branch|target refs|detach|rebase|index|HEAD|delet|submodule"
                ):
                    operator._reject_cross_branch_mutation_target(
                        arguments[0], arguments[1:], attempt["branch"]
                    )

    def test_grabowski_git_branch_attempt_allows_bound_target_with_foreign_startpoint(self) -> None:
        operator = _load_operator_module()
        operator._reject_cross_branch_mutation_target(
            "branch", ["-f", "feature", "refs/heads/base"], "feature"
        )
        operator._reject_cross_branch_mutation_target(
            "update-ref", ["refs/heads/feature", "b" * 40], "feature"
        )
        operator._reject_cross_branch_mutation_target(
            "symbolic-ref", ["HEAD", "refs/heads/feature"], "feature"
        )
        operator._reject_cross_branch_mutation_target(
            "checkout", ["HEAD", "--", "README.md"], "feature"
        )

    def test_git_branch_preimage_represents_unborn_head(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(
                ["git", "init", "-q", "-b", "feature", str(repo)], check=True
            )
            preimage = operator._git_branch_preimage(repo)
        self.assertEqual("feature", preimage["branch"])
        self.assertIsNone(preimage["head"])
        self.assertEqual("unborn", preimage["head_state"])
        self.assertRegex(preimage["preimage_sha256"], r"^[0-9a-f]{64}$")

    def test_git_branch_preimage_binds_unstaged_tracked_worktree_content(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(
                ["git", "init", "-q", "-b", "feature", str(repo)], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"],
                check=True,
            )
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "user.email",
                    "grabowski@example.invalid",
                ],
                check=True,
            )
            readme = repo / "README.md"
            readme.write_text("baseline\n", encoding="utf-8")
            operator.subprocess.run(
                ["git", "-C", str(repo), "add", "README.md"], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
                check=True,
            )

            before = operator._git_branch_preimage(repo)
            readme.write_text("unsaved\n", encoding="utf-8")
            after = operator._git_branch_preimage(repo)

        self.assertEqual(before["head"], after["head"])
        self.assertEqual(before["index_sha256"], after["index_sha256"])
        self.assertNotEqual(
            before["worktree_sha256"], after["worktree_sha256"]
        )
        self.assertNotEqual(before["preimage_sha256"], after["preimage_sha256"])

    def test_grabowski_git_stale_preimage_preserves_normalized_eol_bytes_before_checkout(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(
                ["git", "init", "-q", "-b", "feature", str(repo)], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"],
                check=True,
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "grabowski@example.invalid"],
                check=True,
            )
            (repo / ".gitattributes").write_text("README.md text eol=lf\n", encoding="utf-8")
            readme = repo / "README.md"
            readme.write_bytes(b"baseline\n")
            operator.subprocess.run(
                ["git", "-C", str(repo), "add", ".gitattributes", "README.md"], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"], check=True
            )
            preimage = operator._git_branch_preimage(repo)
            readme.write_bytes(b"baseline\r\n")
            semantic_diff = operator.subprocess.run(
                ["git", "-C", str(repo), "diff", "--", "README.md"],
                stdout=operator.subprocess.PIPE,
                check=True,
            )
            self.assertEqual(b"", semantic_diff.stdout)

            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="a" * 64),
            ):
                result = operator.grabowski_git(
                    str(repo),
                    ["checkout", "HEAD", "--", "README.md"],
                    branch_attempt={
                        "schema_version": 1,
                        "owner_id": "operator:worktree-eol-preimage",
                        "operation_id": "operation-a",
                        "attempt_id": "attempt-1",
                        "branch": "feature",
                        "expected_preimage_sha256": preimage["preimage_sha256"],
                    },
                )

            receipt = result["branch_mutation"]
            self.assertEqual("reconcile_required", receipt["status"])
            self.assertFalse(receipt["effect_attempted"])
            self.assertEqual(b"baseline\r\n", readme.read_bytes())

    def test_grabowski_git_stale_preimage_preserves_assume_unchanged_edit_before_checkout(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(
                ["git", "init", "-q", "-b", "feature", str(repo)], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "grabowski@example.invalid"],
                check=True,
            )
            readme = repo / "README.md"
            readme.write_text("baseline\n", encoding="utf-8")
            operator.subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "update-index", "--assume-unchanged", "README.md"], check=True
            )
            preimage = operator._git_branch_preimage(repo)
            readme.write_text("unsaved\n", encoding="utf-8")
            semantic_diff = operator.subprocess.run(
                ["git", "-C", str(repo), "diff", "--", "README.md"],
                stdout=operator.subprocess.PIPE,
                check=True,
            )
            self.assertEqual(b"", semantic_diff.stdout)

            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="a" * 64),
            ):
                result = operator.grabowski_git(
                    str(repo),
                    ["checkout", "HEAD", "--", "README.md"],
                    branch_attempt={
                        "schema_version": 1,
                        "owner_id": "operator:worktree-assume-preimage",
                        "operation_id": "operation-a",
                        "attempt_id": "attempt-1",
                        "branch": "feature",
                        "expected_preimage_sha256": preimage["preimage_sha256"],
                    },
                )

            receipt = result["branch_mutation"]
            self.assertEqual("reconcile_required", receipt["status"])
            self.assertFalse(receipt["effect_attempted"])
            self.assertEqual("unsaved\n", readme.read_text(encoding="utf-8"))

    def test_grabowski_git_stale_preimage_preserves_unstaged_edit_before_checkout(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(
                ["git", "init", "-q", "-b", "feature", str(repo)], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"],
                check=True,
            )
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "user.email",
                    "grabowski@example.invalid",
                ],
                check=True,
            )
            readme = repo / "README.md"
            readme.write_text("baseline\n", encoding="utf-8")
            operator.subprocess.run(
                ["git", "-C", str(repo), "add", "README.md"], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
                check=True,
            )
            preimage = operator._git_branch_preimage(repo)
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="a" * 64),
            ):
                clean_result = operator.grabowski_git(
                    str(repo),
                    ["checkout", "HEAD", "--", "README.md"],
                    branch_attempt={
                        "schema_version": 1,
                        "owner_id": "operator:worktree-preimage-clean",
                        "operation_id": "operation-clean",
                        "attempt_id": "attempt-clean",
                        "branch": "feature",
                        "expected_preimage_sha256": preimage["preimage_sha256"],
                    },
                )
            clean_receipt = clean_result["branch_mutation"]
            self.assertEqual("completed", clean_receipt["status"])
            self.assertTrue(clean_receipt["effect_attempted"])
            self.assertEqual("baseline\n", readme.read_text(encoding="utf-8"))

            preimage = operator._git_branch_preimage(repo)
            readme.write_text("unsaved\n", encoding="utf-8")

            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="a" * 64),
            ):
                result = operator.grabowski_git(
                    str(repo),
                    ["checkout", "HEAD", "--", "README.md"],
                    branch_attempt={
                        "schema_version": 1,
                        "owner_id": "operator:worktree-preimage",
                        "operation_id": "operation-a",
                        "attempt_id": "attempt-1",
                        "branch": "feature",
                        "expected_preimage_sha256": preimage["preimage_sha256"],
                    },
                )

            receipt = result["branch_mutation"]
            self.assertEqual("reconcile_required", receipt["status"])
            self.assertEqual("git-preimage-drift-before-effect", receipt["reason"])
            self.assertFalse(receipt["effect_attempted"])
            self.assertNotEqual(
                preimage["preimage_sha256"], receipt["observed_preimage_sha256"]
            )
            self.assertEqual("unsaved\n", readme.read_text(encoding="utf-8"))

    def test_grabowski_git_same_owner_competing_attempt_blocks_before_second_effect(self) -> None:
        operator = _load_operator_module()
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            resource_db = root / "resources.sqlite3"
            operator.subprocess.run(["git", "init", "-q", "-b", "feature", str(repo)], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "config", "user.name", "Grabowski Test"], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "config", "user.email", "grabowski@example.invalid"], check=True)
            (repo / "README.md").write_text("baseline\n")
            operator.subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "baseline"], check=True)

            preimage = operator._git_branch_preimage(repo)
            first_attempt = {
                "schema_version": 1,
                "owner_id": "operator:same-owner",
                "operation_id": "operation-a",
                "attempt_id": "attempt-1",
                "branch": "feature",
                "expected_preimage_sha256": preimage["preimage_sha256"],
            }
            second_attempt = {
                **first_attempt,
                "operation_id": "operation-b",
                "attempt_id": "attempt-2",
            }
            entered_effect = threading.Event()
            allow_effect = threading.Event()
            original_run = operator._run
            first_result: dict[str, object] = {}
            first_error: list[BaseException] = []

            def delayed_run(command, **kwargs):
                if "commit" in command:
                    entered_effect.set()
                    if not allow_effect.wait(timeout=2):
                        raise TimeoutError("test did not release first branch effect")
                return original_run(command, **kwargs)

            def execute_first() -> None:
                try:
                    first_result.update(
                        operator.grabowski_git(
                            str(repo),
                            ["commit", "--allow-empty", "-m", "attempt one"],
                            branch_attempt=first_attempt,
                        )
                    )
                except BaseException as exc:  # pragma: no cover - surfaced below
                    first_error.append(exc)

            with (
                patch.object(resources, "RESOURCE_DB", resource_db),
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="a" * 64),
                patch.object(operator, "_run", side_effect=delayed_run),
            ):
                thread = threading.Thread(target=execute_first)
                thread.start()
                self.assertTrue(entered_effect.wait(timeout=2))
                duplicate_result = operator.grabowski_git(
                    str(repo),
                    ["commit", "--allow-empty", "-m", "attempt one duplicate"],
                    branch_attempt=first_attempt,
                )
                second_result = operator.grabowski_git(
                    str(repo),
                    ["commit", "--allow-empty", "-m", "attempt two"],
                    branch_attempt=second_attempt,
                )
                allow_effect.set()
                thread.join(timeout=2)

            self.assertFalse(thread.is_alive())
            self.assertEqual([], first_error)
            self.assertEqual(0, first_result["returncode"])
            first_receipt = first_result["branch_mutation"]
            self.assertEqual("completed", first_receipt["status"])
            self.assertTrue(first_receipt["effect_attempted"])
            self.assertEqual("operation-a", first_receipt["operation_id"])
            self.assertEqual("attempt-1", first_receipt["attempt_id"])
            self.assertEqual(preimage["preimage_sha256"], first_receipt["expected_preimage_sha256"])

            duplicate_receipt = duplicate_result["branch_mutation"]
            self.assertEqual("reconcile_required", duplicate_receipt["status"])
            self.assertEqual(
                "same-owner-attempt-already-running", duplicate_receipt["reason"]
            )
            self.assertFalse(duplicate_receipt["effect_attempted"])
            self.assertFalse(duplicate_receipt["retry_allowed"])
            self.assertEqual("operation-a", duplicate_receipt["operation_id"])
            self.assertEqual("attempt-1", duplicate_receipt["attempt_id"])
            self.assertEqual(
                first_receipt["attempt_binding_sha256"],
                duplicate_receipt["existing_attempt_binding_sha256"],
            )

            second_receipt = second_result["branch_mutation"]
            self.assertEqual("reconcile_required", second_receipt["status"])
            self.assertEqual("same-owner-attempt-conflict", second_receipt["reason"])
            self.assertFalse(second_receipt["effect_attempted"])
            self.assertFalse(second_receipt["retry_allowed"])
            self.assertEqual("operation-b", second_receipt["operation_id"])
            self.assertEqual("attempt-2", second_receipt["attempt_id"])
            self.assertEqual(
                first_receipt["attempt_binding_sha256"],
                second_receipt["existing_attempt_binding_sha256"],
            )

            commits = operator.subprocess.run(
                ["git", "-C", str(repo), "rev-list", "--count", "HEAD"],
                stdout=operator.subprocess.PIPE,
                check=True,
                text=True,
            )
            self.assertEqual("2", commits.stdout.strip())

    def test_grabowski_git_preserves_existing_work_lane_branch_lease(self) -> None:
        operator = _load_operator_module()
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            resource_db = root / "resources.sqlite3"
            operator.subprocess.run(
                ["git", "init", "-q", "-b", "feature", str(repo)], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Grabowski Test"],
                check=True,
            )
            operator.subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "config",
                    "user.email",
                    "grabowski@example.invalid",
                ],
                check=True,
            )
            (repo / "README.md").write_text("baseline\n")
            operator.subprocess.run(
                ["git", "-C", str(repo), "add", "README.md"], check=True
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "commit", "-q", "-m", "baseline"],
                check=True,
            )
            lane_id = "c" * 32
            owner = f"lane:{lane_id}"
            branch_key = f"repo:{repo}:branch:feature"
            lane_metadata = {
                "schema_version": 1,
                "kind": "grabowski.work_lane",
                "lane_id": lane_id,
                "repo": str(repo),
                "target_path": str(repo),
            }

            with (
                patch.object(resources, "RESOURCE_DB", resource_db),
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="c" * 64),
            ):
                resources.acquire_resources(
                    owner,
                    [branch_key],
                    purpose="work lane writer authority",
                    ttl_seconds=120,
                    metadata=lane_metadata,
                )
                with resources._database() as connection:
                    original = connection.execute(
                        "SELECT * FROM leases WHERE resource_key=?", (branch_key,)
                    ).fetchone()
                self.assertIsNotNone(original)
                original_record = dict(original)
                preimage = operator._git_branch_preimage(repo)
                result = operator.grabowski_git(
                    str(repo),
                    ["commit", "--allow-empty", "-m", "work lane mutation"],
                    branch_attempt={
                        "schema_version": 1,
                        "owner_id": owner,
                        "operation_id": "operation-a",
                        "attempt_id": "attempt-1",
                        "branch": "feature",
                        "expected_preimage_sha256": preimage["preimage_sha256"],
                    },
                )
                with resources._database() as connection:
                    restored = connection.execute(
                        "SELECT * FROM leases WHERE resource_key=?", (branch_key,)
                    ).fetchone()

            self.assertEqual(0, result["returncode"])
            receipt = result["branch_mutation"]
            self.assertEqual("completed", receipt["status"])
            self.assertEqual("preexisting", receipt["lease_origin"])
            self.assertEqual("restored", receipt["lease_cleanup"]["action"])
            self.assertFalse(receipt["release_required_after_terminal_readback"])
            self.assertIsNotNone(restored)
            self.assertEqual(original_record["purpose"], restored["purpose"])
            self.assertEqual(
                original_record["acquired_at_unix"], restored["acquired_at_unix"]
            )
            self.assertEqual(
                original_record["updated_at_unix"], restored["updated_at_unix"]
            )
            self.assertEqual(
                original_record["expires_at_unix"], restored["expires_at_unix"]
            )
            self.assertEqual(
                original_record["metadata_sha256"], restored["metadata_sha256"]
            )
            self.assertEqual(original_record["metadata_json"], restored["metadata_json"])

    def test_grabowski_git_same_attempt_continuation_preserves_unchanged_preimage(self) -> None:
        operator = _load_operator_module()
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            resource_db = root / "resources.sqlite3"
            operator.subprocess.run(["git", "init", "-q", "-b", "feature", str(repo)], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "config", "user.name", "Grabowski Test"], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "config", "user.email", "grabowski@example.invalid"], check=True)
            (repo / "README.md").write_text("baseline\n")
            operator.subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "baseline"], check=True)
            preimage = operator._git_branch_preimage(repo)
            attempt = {
                "schema_version": 1,
                "owner_id": "operator:same-owner",
                "operation_id": "operation-a",
                "attempt_id": "attempt-1",
                "branch": "feature",
                "expected_preimage_sha256": preimage["preimage_sha256"],
            }

            with (
                patch.object(resources, "RESOURCE_DB", resource_db),
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_append_effect_audit", return_value="b" * 64),
            ):
                first = operator.grabowski_git(
                    str(repo), ["update-index", "--refresh"], branch_attempt=attempt
                )
                second = operator.grabowski_git(
                    str(repo), ["update-index", "--refresh"], branch_attempt=attempt
                )

            self.assertEqual("completed", first["branch_mutation"]["status"])
            self.assertEqual("completed", second["branch_mutation"]["status"])
            self.assertEqual(
                first["branch_mutation"]["attempt_binding_sha256"],
                second["branch_mutation"]["attempt_binding_sha256"],
            )
            self.assertEqual(
                preimage["preimage_sha256"], second["branch_mutation"]["postimage_sha256"]
            )

    def test_grabowski_git_cleans_attempt_lease_when_post_acquire_preimage_read_fails(self) -> None:
        operator = _load_operator_module()
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(["git", "init", "-q", "-b", "feature", str(repo)], check=True)
            preimage = operator._git_branch_preimage(repo)
            attempt = {
                "schema_version": 1,
                "owner_id": "operator:preimage-cleanup",
                "operation_id": "operation-a",
                "attempt_id": "attempt-1",
                "branch": "feature",
                "expected_preimage_sha256": preimage["preimage_sha256"],
            }
            lease = {
                "resource_key": "repo:/tmp/repo:branch:feature",
                "attempt_binding_sha256": "b" * 64,
                "lease": {"metadata_sha256": "c" * 64, "expires_at_unix": 9999999999},
            }
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_validate_argv", side_effect=lambda argv, cwd: argv),
                patch.object(
                    operator,
                    "_git_branch_preimage",
                    side_effect=[preimage, RuntimeError("post-acquire read failed")],
                ),
                patch.object(resources, "acquire_branch_mutation_attempt", return_value=lease),
                patch.object(
                    resources,
                    "complete_branch_mutation_attempt",
                    return_value={"action": "released"},
                ) as cleanup,
            ):
                with self.assertRaisesRegex(RuntimeError, "post-acquire read failed"):
                    operator.grabowski_git(
                        str(repo),
                        ["update-index", "--refresh"],
                        branch_attempt=attempt,
                    )
            cleanup.assert_called_once_with(lease)

    def test_grabowski_git_validates_command_before_attempt_lease_acquisition(self) -> None:
        operator = _load_operator_module()
        import grabowski_resources as resources

        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            operator.subprocess.run(["git", "init", "-q", "-b", "feature", str(repo)], check=True)
            preimage = operator._git_branch_preimage(repo)
            attempt = {
                "schema_version": 1,
                "owner_id": "operator:validation-order",
                "operation_id": "operation-a",
                "attempt_id": "attempt-1",
                "branch": "feature",
                "expected_preimage_sha256": preimage["preimage_sha256"],
            }
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(
                    operator,
                    "_validate_argv",
                    side_effect=PermissionError("blocked before lease"),
                ),
                patch.object(resources, "acquire_branch_mutation_attempt") as acquire,
            ):
                with self.assertRaisesRegex(PermissionError, "before lease"):
                    operator.grabowski_git(
                        str(repo),
                        ["update-index", "--refresh"],
                        branch_attempt=attempt,
                    )
            acquire.assert_not_called()

    def test_grabowski_git_uses_sanitized_git_environment(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            environment = {"PATH": "/usr/bin", "GIT_TERMINAL_PROMPT": "0"}
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_guard_git", return_value=None),
                patch.object(operator, "_validate_argv", side_effect=lambda argv, cwd: argv),
                patch.object(operator, "_git_environment", return_value=environment),
                patch.object(operator, "_run", return_value={"returncode": 0}) as run,
            ):
                operator.grabowski_git(str(repo), ["status"])
        self.assertEqual(run.call_args.kwargs["environment"], environment)

    def test_grabowski_git_push_disables_hooks_helpers_and_unsafe_protocols(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            environment = {"PATH": "/usr/bin"}
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_guard_git", return_value=None),
                patch.object(operator, "_validate_argv", side_effect=lambda argv, cwd: argv),
                patch.object(operator, "_git_push_environment", return_value=environment),
                patch.object(operator, "_run", return_value={"returncode": 0}) as run,
            ):
                operator.grabowski_git(
                    str(repo),
                    ["push", "origin", "HEAD:refs/heads/feature"],
                )
        command = run.call_args.args[0]
        self.assertIn("core.hooksPath=/dev/null", command)
        self.assertIn("core.fsmonitor=false", command)
        self.assertIn("protocol.ext.allow=never", command)
        self.assertIn("remote.origin.mirror=false", command)
        self.assertIn("remote.origin.receivepack=git-receive-pack", command)
        self.assertNotIn("remote.origin.push=", command)
        self.assertIn("push.followTags=false", command)
        self.assertIn("push.pushOption=", command)
        self.assertIn("push.gpgSign=false", command)
        self.assertIn("push.recurseSubmodules=no", command)
        self.assertEqual(environment, run.call_args.kwargs["environment"])

    def test_grabowski_git_safe_dry_run_does_not_inject_empty_remote_push_refspec(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bare = root / "remote.git"
            repo = root / "repo"
            fake_ssh = root / "fake-ssh.py"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import os, shlex, sys\n"
                "command = shlex.split(sys.argv[-1])\n"
                "if len(command) != 2 or command[0] != 'git-receive-pack':\n"
                "    raise SystemExit(64)\n"
                "os.execvp(command[0], command)\n"
            )
            fake_ssh.chmod(0o700)
            operator.subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "config", "user.name", "Grabowski Test"], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "config", "user.email", "grabowski@example.invalid"], check=True)
            (repo / "README.md").write_text("push safety dry run\n")
            operator.subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
            operator.subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "test"], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", f"ssh://test.invalid{bare}"],
                check=True,
            )
            environment = operator._git_push_environment()
            environment["GIT_SSH_COMMAND"] = str(fake_ssh)
            with (
                patch.object(operator, "_require_operator_mutation", return_value=None),
                patch.object(operator, "_git_push_environment", return_value=environment),
            ):
                result = operator.grabowski_git(
                    str(repo),
                    ["push", "--dry-run", "origin", "HEAD:refs/heads/feature"],
                )
            self.assertEqual(0, result["returncode"], result.get("stderr"))
            remote_head = operator.subprocess.run(
                ["git", "--git-dir", str(bare), "rev-parse", "--verify", "refs/heads/feature"],
                stdout=operator.subprocess.PIPE,
                stderr=operator.subprocess.PIPE,
                check=False,
                text=True,
            )
            self.assertNotEqual(0, remote_head.returncode)

    def test_git_push_environment_disables_executable_transport_overrides(self) -> None:
        operator = _load_operator_module()
        injected = {
            "PATH": "/usr/bin",
            "GIT_SSH": "/tmp/evil-ssh",
            "GIT_SSH_COMMAND": "/tmp/evil-command",
            "GIT_PROXY_COMMAND": "/tmp/evil-proxy",
            "GIT_ASKPASS": "/tmp/evil-askpass",
            "SSH_ASKPASS": "/tmp/evil-ssh-askpass",
            "GIT_ALLOW_PROTOCOL": "ext:file:ssh:https",
        }
        with patch.object(operator, "_git_environment", return_value=injected):
            environment = operator._git_push_environment()
        self.assertNotIn("GIT_SSH", environment)
        self.assertNotIn("GIT_PROXY_COMMAND", environment)
        self.assertEqual("/usr/bin/ssh -F /dev/null -oBatchMode=yes -oProxyCommand=none -oPermitLocalCommand=no -oClearAllForwardings=yes", environment["GIT_SSH_COMMAND"])
        self.assertEqual("ssh", environment["GIT_SSH_VARIANT"])
        self.assertEqual("/bin/false", environment["GIT_ASKPASS"])
        self.assertEqual("/bin/false", environment["SSH_ASKPASS"])
        self.assertEqual("ssh", environment["GIT_ALLOW_PROTOCOL"])

    def test_benign_global_config_and_normal_feature_push_remain_allowed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            operator.subprocess.run(["git", "init", "-q", str(repo)], check=True)
            operator.subprocess.run(
                ["git", "-C", str(repo), "symbolic-ref", "HEAD", "refs/heads/feature"],
                check=True,
            )
            operator.subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "git@github.com:heimgewebe/grabowski.git"],
                check=True,
            )
            operator._guard_git(["-c", "core.pager=cat", "status"], repo)
            operator._guard_git(
                ["push", "origin", "HEAD:refs/heads/feature"],
                repo,
            )

    def test_privileged_reference_has_expiry_replay_policy_and_bound_hash(self) -> None:
        operator = _load_operator_module()
        with (
            patch.object(operator, "_require_operator_capability", return_value=None),
            patch.object(operator.time, "time", return_value=1_700_000_000),
        ):
            payload = operator.grabowski_privileged_action_reference(
                "reset_failed_systemd_unit",
                "user@111.service",
                "document external approval request",
            )

        self.assertEqual(payload["created_at_unix"], 1_700_000_000)
        self.assertEqual(payload["expires_at_unix"], 1_700_000_900)
        self.assertEqual(payload["replay_policy"], "single-use-external-broker")
        material = {
            key: value
            for key, value in payload.items()
            if key != "reference_sha256"
        }
        expected = hashlib.sha256(
            json.dumps(
                material,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(payload["reference_sha256"], expected)


class DurableJobFinalizationReceiptTests(unittest.TestCase):
    def _systemd_not_found(self, root: Path) -> dict[str, object]:
        return {
            "returncode": 0,
            "stdout": (
                "LoadState=not-found\n"
                "ActiveState=inactive\n"
                "SubState=dead\n"
                "Result=success\n"
                "ExecMainCode=0\n"
                "ExecMainStatus=0\n"
            ),
            "stderr": "",
            "argv": [],
            "argv_sha256": "1" * 64,
            "command": "systemctl show",
            "cwd": str(root),
            "timed_out": False,
            "duration_seconds": 0.01,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    def _systemd_visible_success(self, root: Path) -> dict[str, object]:
        result = self._systemd_not_found(root)
        result["stdout"] = (
            "LoadState=loaded\n"
            "ActiveState=inactive\n"
            "SubState=dead\n"
            "Result=success\n"
            "ExecMainCode=0\n"
            "ExecMainStatus=0\n"
        )
        return result

    def _fixture(
        self,
        operator,
        root: Path,
        *,
        final_status: str = "completed",
        write_receipt: bool = True,
        raw_receipt: bytes | None = None,
        mutate_payload=None,
    ) -> tuple[Path, Path, str, str]:
        state = root / "state"
        jobs = state / "jobs"
        unit = "grabowski-job-deadbeefcafe"
        directory = jobs / unit
        directory.mkdir(parents=True)
        expected_head = "a" * 40
        argv = [
            "/usr/bin/python3",
            "/repo/tools/run_scheduled_deploy.py",
            "--repo",
            "/repo",
            "--expected-head",
            expected_head,
            "--delay-seconds",
            "8",
        ]
        argv_sha256 = operator._argv_hash(argv)
        stdout_path = directory / "stdout.log"
        stderr_path = directory / "stderr.log"
        stdout_path.write_text("runner output\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        contract = operator._job_finalization_contract(
            unit=unit,
            directory=directory,
            argv_sha256=argv_sha256,
            expected_head=expected_head,
        )
        metadata = {
            "schema_version": 1,
            "unit": unit,
            "job_id": "deadbeefcafe",
            "owner": "uid:1000",
            "argv": argv,
            "argv_sha256": argv_sha256,
            "command": " ".join(argv),
            "cwd": str(root),
            "runtime_seconds": 3600,
            "created_at_unix": 1000,
            "started_at": "1970-01-01T00:16:40Z",
            "started_at_unix": 1000,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "scope": {
                "cwd": str(root),
                "argv_sha256": argv_sha256,
                "runtime_seconds": 3600,
            },
            "finalization_contract": contract,
            "final_status": "launch_submitted",
            "notify_on_done": {
                "requested": False,
                "channels": [],
                "delivery_mode": "metadata_only",
                "delivery_enabled": False,
                "does_not_establish": [
                    "notification_sent",
                    "notification_delivery",
                    "job_success",
                ],
            },
        }
        (directory / "metadata.json").write_text(
            json.dumps(metadata), encoding="utf-8"
        )
        if write_receipt:
            finalization_path = directory / "finalization.json"
            if raw_receipt is not None:
                finalization_path.write_bytes(raw_receipt)
            else:
                material = {
                    "schema_version": 1,
                    "kind": operator.RUNTIME_DEPLOY_FINALIZATION_KIND,
                    "unit": unit,
                    "job_id": "deadbeefcafe",
                    "argv_sha256": argv_sha256,
                    "expected_head": expected_head,
                    "receipt_paths": operator._job_receipt_paths(directory),
                    "final_status": final_status,
                    "completion_status": (
                        "complete" if final_status == "completed" else "failed"
                    ),
                    "repo_head": expected_head if final_status == "completed" else None,
                    "release_id": "release-test" if final_status == "completed" else None,
                    "failure_type": None if final_status == "completed" else "RuntimeError",
                    "timestamp_unix": 1001,
                }
                if mutate_payload is not None:
                    mutate_payload(material)
                payload = {
                    **material,
                    "payload_sha256": operator._json_sha256(material),
                }
                finalization_path.write_text(
                    json.dumps(payload), encoding="utf-8"
                )
        return state, jobs, unit, expected_head

    def _status(self, operator, state: Path, jobs: Path, unit: str, result: dict[str, object]):
        with patch.object(operator, "STATE_DIR", state), patch.object(
            operator, "JOBS_DIR", jobs
        ), patch.object(operator, "_run", return_value=result):
            return operator.grabowski_job_status(unit)

    def _generic_fixture(
        self,
        operator,
        root: Path,
        *,
        final_status: str = "succeeded",
        write_receipt: bool = True,
        mutate_contract=None,
        mutate_payload=None,
        launch_failed: bool = False,
    ) -> tuple[Path, Path, str]:
        state = root / "state"
        jobs = state / "jobs"
        unit = "grabowski-job-cafebabefeed"
        directory = jobs / unit
        directory.mkdir(parents=True)
        argv = ["python3", "-c", "print(1)"]
        argv_sha256 = operator._argv_hash(argv)
        contract = operator._generic_job_finalization_contract(
            unit=unit, directory=directory, argv_sha256=argv_sha256
        )
        if mutate_contract is not None:
            mutate_contract(contract)
        terminalization = {
            "source": "systemd-run-launch",
            "query_valid": False,
            "systemd_visible": False,
            "final_status": "launch_submitted",
        }
        metadata = {
            "schema_version": 2,
            "unit": unit,
            "job_id": "cafebabefeed",
            "owner": "uid:1000",
            "argv": argv,
            "argv_sha256": argv_sha256,
            "command": "python3 -c print(1)",
            "cwd": str(root),
            "runtime_seconds": 60,
            "created_at_unix": 1000,
            "started_at": "1970-01-01T00:16:40Z",
            "started_at_unix": 1000,
            "stdout_path": str(directory / "stdout.log"),
            "stderr_path": str(directory / "stderr.log"),
            "scope": {"cwd": str(root), "argv_sha256": argv_sha256, "runtime_seconds": 60},
            "expected_receipt": {"finalization_path": str(directory / "finalization.json")},
            "finalization_contract": contract,
            "final_status": "launch_submitted",
            "terminalization_evidence": terminalization,
            "notify_on_done": {
                "requested": False,
                "channels": [],
                "delivery_mode": "metadata_only",
                "delivery_enabled": False,
                "does_not_establish": ["notification_sent", "notification_delivery", "job_success"],
            },
        }
        if launch_failed:
            metadata["final_status"] = "launch_failed"
            metadata["terminalization_evidence"] = {
                **terminalization,
                "source": "systemd-run-launch-failure",
                "final_status": "launch_failed",
            }
        (directory / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
        if write_receipt:
            material = {
                **contract,
                "final_status": final_status,
                "completion_status": "complete" if final_status == "succeeded" else "failed",
                "failure_type": None if final_status == "succeeded" else final_status,
                "timestamp_unix": 1001,
            }
            if mutate_payload is not None:
                mutate_payload(material)
            payload = {**material, "payload_sha256": operator._json_sha256(material)}
            (directory / "finalization.json").write_text(json.dumps(payload), encoding="utf-8")
        return state, jobs, unit

    def test_generic_collected_success_and_delayed_read_are_stable(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit = self._generic_fixture(operator, root)
            first = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
            second = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
        self.assertEqual(first["final_status"], "succeeded")
        self.assertEqual(second["final_status"], "succeeded")
        self.assertTrue(first["finalization_receipt"]["valid"])
        self.assertTrue(first["terminalization_evidence"]["fallback_used"])

    def test_generic_collected_failure_preserves_failure_type(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit = self._generic_fixture(
                operator, root, final_status="failed"
            )
            status = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
        self.assertEqual(status["final_status"], "failed")
        self.assertEqual(status["finalization_receipt"]["failure_type"], "failed")

    def test_generic_missing_or_invalid_contract_receipt_fails_closed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit = self._generic_fixture(
                operator, root, write_receipt=False
            )
            missing = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
        self.assertEqual(missing["final_status"], "missing_finalization_evidence")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit = self._generic_fixture(
                operator,
                root,
                mutate_contract=lambda contract: contract.__setitem__("contract_sha256", "0" * 64),
            )
            invalid = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
        self.assertEqual(invalid["final_status"], "missing_finalization_evidence")
        self.assertEqual(invalid["finalization_receipt"]["reason"], "contract_sha256_mismatch")

    def test_generic_receipt_binding_and_primary_status_rules(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def mutate(material):
                material["contract_sha256"] = "1" * 64
            state, jobs, unit = self._generic_fixture(
                operator, root, mutate_payload=mutate
            )
            invalid = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
        self.assertEqual(invalid["final_status"], "missing_finalization_evidence")
        self.assertEqual(
            invalid["finalization_receipt"]["reason"],
            "receipt_binding_mismatch:contract_sha256",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit = self._generic_fixture(
                operator, root, final_status="failed"
            )
            visible = self._status(operator, state, jobs, unit, self._systemd_visible_success(root))
        self.assertEqual(visible["final_status"], "succeeded")
        self.assertEqual(visible["terminalization_evidence"]["source"], "systemd-show")

    def test_launch_failure_metadata_precedes_generic_receipt_fallback(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit = self._generic_fixture(
                operator, root, launch_failed=True
            )
            status = self._status(operator, state, jobs, unit, self._systemd_not_found(root))
        self.assertEqual(status["final_status"], "launch_failed")
        self.assertEqual(
            status["terminalization_evidence"]["source"],
            "systemd-run-launch-failure",
        )

    def test_collected_unit_with_valid_bound_complete_receipt_is_completed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, expected_head = self._fixture(operator, root)
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "completed")
        self.assertEqual(
            status["terminalization_evidence"]["source"],
            "persisted-runner-receipt",
        )
        self.assertTrue(status["terminalization_evidence"]["fallback_used"])
        self.assertEqual(
            status["terminalization_evidence"]["expected_head"], expected_head
        )
        self.assertTrue(status["finalization_receipt"]["valid"])

    def test_collected_unit_without_receipt_stays_missing_finalization_evidence(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(
                operator, root, write_receipt=False
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(status["finalization_receipt"]["state"], "missing_receipt")
        self.assertFalse(status["terminalization_evidence"]["fallback_used"])

    def test_wrong_expected_head_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def mutate(material):
                material["expected_head"] = "c" * 40
                material["repo_head"] = "c" * 40
            state, jobs, unit, _ = self._fixture(
                operator, root, mutate_payload=mutate
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(
            status["finalization_receipt"]["reason"],
            "receipt_binding_mismatch:expected_head",
        )

    def test_wrong_argv_sha256_or_job_id_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        for key, wrong in (("argv_sha256", "d" * 64), ("job_id", "feedfacecafe")):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                def mutate(material, key=key, wrong=wrong):
                    material[key] = wrong
                state, jobs, unit, _ = self._fixture(
                    operator, root, mutate_payload=mutate
                )
                status = self._status(
                    operator, state, jobs, unit, self._systemd_not_found(root)
                )
                self.assertEqual(
                    status["final_status"], "missing_finalization_evidence"
                )
                self.assertEqual(
                    status["finalization_receipt"]["reason"],
                    f"receipt_binding_mismatch:{key}",
                )

    def test_failed_receipt_maps_to_failed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(
                operator, root, final_status="failed"
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "failed")
        self.assertEqual(
            status["terminalization_evidence"]["source"],
            "persisted-runner-receipt",
        )
        self.assertTrue(status["finalization_receipt"]["valid"])

    def test_runtime_deploy_outcome_unknown_preserves_applied_identity_and_blocks_retry(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def mutate(material):
                expected_head = material["expected_head"]
                receipt_sha256 = "ab" * 32
                material.update(
                    {
                        "completion_status": "outcome_unknown",
                        "repo_head": expected_head,
                        "release_id": "release-test",
                        "failure_type": "ProductionBlueGreenReceiptPersistenceError",
                        "blue_green": {
                            "schema_version": 1,
                            "kind": "grabowski_scheduled_blue_green_summary",
                            "receipt_sha256": receipt_sha256,
                            "receipt_path": None,
                            "receipt_persisted": False,
                            "receipt_persistence_error_type": "OSError",
                            "blind_retry_allowed": False,
                            "outcome": "completed",
                            "expected_head": expected_head,
                            "source_identity_sha256": "cd" * 32,
                        },
                        "blue_green_receipt_sha256": receipt_sha256,
                        "blind_retry_allowed": False,
                    }
                )

            state, jobs, unit, expected_head = self._fixture(
                operator,
                root,
                final_status="outcome_unknown",
                mutate_payload=mutate,
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "outcome_unknown")
        self.assertEqual(
            status["terminalization_evidence"]["source"],
            "persisted-runner-receipt",
        )
        self.assertEqual(
            status["terminalization_evidence"]["expected_head"], expected_head
        )
        self.assertTrue(status["finalization_receipt"]["valid"])
        self.assertFalse(status["finalization_receipt"]["blind_retry_allowed"])
        self.assertEqual(
            status["finalization_receipt"]["blue_green_receipt_sha256"],
            "ab" * 32,
        )

    def test_runtime_deploy_outcome_unknown_accepts_ambiguous_unpersisted_cutover(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def mutate(material):
                expected_head = material["expected_head"]
                receipt_sha256 = "ab" * 32
                material.update(
                    {
                        "completion_status": "outcome_unknown",
                        "repo_head": None,
                        "release_id": None,
                        "failure_type": "BlueGreenDeploymentIncomplete",
                        "blue_green": {
                            "schema_version": 1,
                            "kind": "grabowski_scheduled_blue_green_summary",
                            "receipt_sha256": receipt_sha256,
                            "receipt_path": None,
                            "receipt_persisted": False,
                            "receipt_persistence_error_type": "OSError",
                            "blind_retry_allowed": False,
                            "outcome": "outcome_unknown",
                            "expected_head": expected_head,
                            "source_identity_sha256": "cd" * 32,
                        },
                        "blue_green_receipt_sha256": receipt_sha256,
                        "blind_retry_allowed": False,
                    }
                )

            state, jobs, unit, _ = self._fixture(
                operator, root, final_status="outcome_unknown", mutate_payload=mutate
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "outcome_unknown")
        self.assertTrue(status["finalization_receipt"]["valid"])
        self.assertFalse(status["finalization_receipt"]["blind_retry_allowed"])

    def test_runtime_deploy_outcome_unknown_rejects_retryable_receipt(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def mutate(material):
                expected_head = material["expected_head"]
                receipt_sha256 = "ab" * 32
                material.update(
                    {
                        "completion_status": "outcome_unknown",
                        "repo_head": expected_head,
                        "release_id": "release-test",
                        "failure_type": "ProductionBlueGreenReceiptPersistenceError",
                        "blue_green": {
                            "receipt_sha256": receipt_sha256,
                            "receipt_persisted": False,
                            "outcome": "completed",
                            "expected_head": expected_head,
                        },
                        "blue_green_receipt_sha256": receipt_sha256,
                        "blind_retry_allowed": True,
                    }
                )

            state, jobs, unit, _ = self._fixture(
                operator,
                root,
                final_status="outcome_unknown",
                mutate_payload=mutate,
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(
            status["finalization_receipt"]["reason"],
            "outcome_unknown_receipt_semantics_invalid",
        )

    def test_truncated_or_invalid_json_receipt_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        for raw in (b'{"truncated":', b'not-json'):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state, jobs, unit, _ = self._fixture(
                    operator, root, raw_receipt=raw
                )
                status = self._status(
                    operator, state, jobs, unit, self._systemd_not_found(root)
                )
                self.assertEqual(
                    status["final_status"], "missing_finalization_evidence"
                )
                self.assertEqual(
                    status["finalization_receipt"]["reason"],
                    "receipt_json_invalid",
                )

    def test_symlinked_receipt_is_rejected_fail_closed(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(operator, root)
            receipt = jobs / unit / "finalization.json"
            target = root / "outside-receipt.json"
            target.write_bytes(receipt.read_bytes())
            receipt.unlink()
            receipt.symlink_to(target)
            status = self._status(
                operator, state, jobs, unit, self._systemd_not_found(root)
            )
        self.assertEqual(status["final_status"], "missing_finalization_evidence")
        self.assertEqual(status["finalization_receipt"]["reason"], "receipt_symlink")

    def test_fifo_receipt_is_rejected_without_blocking(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "finalization.json"
            os.mkfifo(fifo, 0o600)
            started = time.monotonic()
            result = operator._read_finalization_receipt_file(fifo)
            duration = time.monotonic() - started
        self.assertLess(duration, 0.5)
        self.assertEqual(result["state"], "invalid_receipt")
        self.assertEqual(result["reason"], "receipt_not_regular_file")

    def test_stale_metadata_temp_cleanup_is_bounded_and_conservative(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "grabowski-job-cleanup0001"
            job.mkdir(mode=0o700)
            stale = job / ("metadata.json." + "a" * 32 + ".tmp")
            fresh = job / ("metadata.json." + "b" * 32 + ".tmp")
            malformed = job / "metadata.json.not-a-uuid.tmp"
            stale.write_text("stale", encoding="utf-8")
            fresh.write_text("fresh", encoding="utf-8")
            malformed.write_text("keep", encoding="utf-8")
            now = 10_000
            os.utime(stale, (now - operator.JOB_METADATA_TEMP_STALE_SECONDS - 1,) * 2)
            os.utime(fresh, (now,) * 2)
            result = operator._cleanup_stale_job_metadata_temps(root, now_unix=now)
            self.assertEqual(result, {"inspected": 2, "removed": 1, "errors": 0})
            self.assertFalse(stale.exists())
            self.assertTrue(fresh.exists())
            self.assertTrue(malformed.exists())

    def test_metadata_temp_cleanup_bounds_nonmatching_entries(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            job = root / "grabowski-job-entrybound01"
            job.mkdir(mode=0o700)
            for index in range(4):
                (job / f"unrelated-{index}").write_text("keep", encoding="utf-8")
            stale = job / ("metadata.json." + "c" * 32 + ".tmp")
            stale.write_text("stale", encoding="utf-8")
            now = 10_000
            os.utime(stale, (now - operator.JOB_METADATA_TEMP_STALE_SECONDS - 1,) * 2)
            with patch.object(operator, "JOB_METADATA_ENTRY_SWEEP_LIMIT", 0):
                result = operator._cleanup_stale_job_metadata_temps(root, now_unix=now)
            self.assertEqual(result["inspected"], 0)
            self.assertTrue(stale.exists())

    def test_visible_systemd_status_remains_primary_over_valid_receipt(self) -> None:
        operator = _load_operator_module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, jobs, unit, _ = self._fixture(
                operator, root, final_status="failed"
            )
            status = self._status(
                operator, state, jobs, unit, self._systemd_visible_success(root)
            )
        self.assertEqual(status["final_status"], "succeeded")
        self.assertEqual(
            status["terminalization_evidence"]["source"], "systemd-show"
        )
        self.assertTrue(status["systemd_visible"])
        self.assertTrue(status["finalization_receipt"]["valid"])


if __name__ == "__main__":
    unittest.main()

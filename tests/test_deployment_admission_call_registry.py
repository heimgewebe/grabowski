from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from tests.test_operator_contract import _load_operator_module


def _sync_tool() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        is_async=False,
        context_kwarg=None,
        annotations=types.SimpleNamespace(readOnlyHint=True),
    )


def _async_tool() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        is_async=True,
        context_kwarg=None,
        annotations=types.SimpleNamespace(readOnlyHint=True),
    )


SAMPLE_ENTRY_KEYS = {
    "identity",
    "tool_name",
    "kind",
    "drain_blocking",
    "started_at_unix",
    "age_seconds",
}
REGISTRY_ENTRY_KEYS = {
    "identity",
    "tool_name",
    "kind",
    "drain_blocking",
    "started_at_unix",
    "started_monotonic",
}


class DeploymentAdmissionCallRegistryTests(unittest.TestCase):
    def test_register_release_active_count_is_registry_length(self) -> None:
        operator = _load_operator_module()
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())
        identity = operator._deployment_admission_register_tool_call(
            "grabowski_read_text", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
        )
        self.assertIsInstance(identity, str)
        self.assertTrue(identity)
        self.assertEqual(1, operator._deployment_admission_active_tool_calls())
        self.assertTrue(
            operator._deployment_admission_release_tool_call(identity)
        )
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_registry_capacity_fails_closed_before_effect(self) -> None:
        operator = _load_operator_module()
        with patch.object(
            operator, "_DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX", 2
        ):
            first = operator._deployment_admission_register_tool_call(
                "first", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
            )
            second = operator._deployment_admission_register_tool_call(
                "second", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
            )
            with self.assertRaisesRegex(RuntimeError, "registry is full"):
                operator._deployment_admission_register_tool_call(
                    "third", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
                )
            self.assertEqual(2, operator._deployment_admission_active_tool_calls())
            self.assertTrue(operator._deployment_admission_release_tool_call(first))
            replacement = operator._deployment_admission_register_tool_call(
                "replacement", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
            )
            self.assertEqual(2, operator._deployment_admission_active_tool_calls())
            self.assertTrue(operator._deployment_admission_release_tool_call(second))
            self.assertTrue(
                operator._deployment_admission_release_tool_call(replacement)
            )

    def test_registry_rejects_non_boolean_drain_classification(self) -> None:
        operator = _load_operator_module()
        with self.assertRaisesRegex(ValueError, "drain_blocking must be boolean"):
            operator._deployment_admission_register_tool_call(
                "read",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
                drain_blocking=1,
            )
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_registry_retries_opaque_identity_collision(self) -> None:
        operator = _load_operator_module()
        repeated = types.SimpleNamespace(hex="a" * 32)
        distinct = types.SimpleNamespace(hex="b" * 32)
        with patch.object(
            operator.uuid, "uuid4", side_effect=[repeated, repeated, distinct]
        ):
            first = operator._deployment_admission_register_tool_call(
                "first", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
            )
            second = operator._deployment_admission_register_tool_call(
                "second", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
            )
        self.assertEqual("a" * 32, first)
        self.assertEqual("b" * 32, second)
        self.assertEqual(2, operator._deployment_admission_active_tool_calls())

    def test_registry_identity_collision_exhaustion_fails_closed(self) -> None:
        operator = _load_operator_module()
        repeated = types.SimpleNamespace(hex="a" * 32)
        with patch.object(operator.uuid, "uuid4", return_value=repeated):
            first = operator._deployment_admission_register_tool_call(
                "first", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
            )
            with self.assertRaisesRegex(RuntimeError, "unique active-call identity"):
                operator._deployment_admission_register_tool_call(
                    "second", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
                )
        self.assertEqual("a" * 32, first)
        self.assertEqual(1, operator._deployment_admission_active_tool_calls())

    def test_release_is_idempotent_pop_by_identity_no_cross_release(self) -> None:
        operator = _load_operator_module()
        first = operator._deployment_admission_register_tool_call(
            "grabowski_read_text", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
        )
        second = operator._deployment_admission_register_tool_call(
            "grabowski_create_text", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        self.assertTrue(operator._deployment_admission_release_tool_call(first))
        self.assertFalse(operator._deployment_admission_release_tool_call(first))
        self.assertEqual(1, operator._deployment_admission_active_tool_calls())
        self.assertTrue(operator._deployment_admission_release_tool_call(second))
        self.assertFalse(operator._deployment_admission_release_tool_call(second))
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())
        self.assertFalse(operator._deployment_admission_release_tool_call("unknown"))
        self.assertFalse(operator._deployment_admission_release_tool_call(None))
        self.assertFalse(operator._deployment_admission_release_tool_call(123))

    def test_registry_stores_only_bounded_safe_metadata(self) -> None:
        operator = _load_operator_module()
        identity = operator._deployment_admission_register_tool_call(
            "grabowski_read_text", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
        )
        entry = operator._deployment_admission_active_registry_snapshot()[identity]
        self.assertEqual(REGISTRY_ENTRY_KEYS, set(entry))
        self.assertEqual("grabowski_read_text", entry["tool_name"])
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC, entry["kind"]
        )
        self.assertTrue(entry["drain_blocking"])
        self.assertIsInstance(entry["started_at_unix"], float)
        self.assertIsInstance(entry["started_monotonic"], float)
        payload = json.dumps(entry)
        for forbidden in ("arguments", "args", "kwargs", "content", "password"):
            self.assertNotIn(forbidden, payload)

    def test_anonymous_and_overlong_tool_names_are_bounded(self) -> None:
        operator = _load_operator_module()
        limit = operator._DEPLOYMENT_ADMISSION_MAX_TOOL_NAME_CHARS
        anonymous = operator._deployment_admission_register_tool_call(
            None, operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        entry = operator._deployment_admission_active_registry_snapshot()[anonymous]
        self.assertEqual("unnamed", entry["tool_name"])
        overlong = "x" * (limit + 100)
        named = operator._deployment_admission_register_tool_call(
            overlong, operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        entry = operator._deployment_admission_active_registry_snapshot()[named]
        self.assertEqual(overlong[:limit], entry["tool_name"])
        self.assertEqual(limit, len(entry["tool_name"]))

        class SensitiveName:
            def __str__(self) -> str:
                raise AssertionError("non-string tool names must not be rendered")

        sensitive = operator._deployment_admission_register_tool_call(
            SensitiveName(), operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        entry = operator._deployment_admission_active_registry_snapshot()[sensitive]
        self.assertEqual("unnamed", entry["tool_name"])

    def test_snapshot_clamps_negative_monotonic_age(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator.time, "monotonic", side_effect=[100.0, 90.0]):
            operator._deployment_admission_register_tool_call(
                "clock-shift", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
            )
            snapshot = operator._deployment_admission_snapshot()
        self.assertEqual(0.0, snapshot["oldest_active_tool_call_age_seconds"])
        self.assertEqual(0.0, snapshot["active_tool_calls_sample"][0]["age_seconds"])

    def test_snapshot_diagnostics_group_and_bound_active_calls(self) -> None:
        operator = _load_operator_module()
        limit = operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_SAMPLE_MAX
        sync_count = limit + 3
        async_count = 2
        for index in range(sync_count):
            operator._deployment_admission_register_tool_call(
                f"sync_tool_{index % 4}",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
            )
        for index in range(async_count):
            operator._deployment_admission_register_tool_call(
                f"async_tool_{index}",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
            )
        total = sync_count + async_count
        snapshot = operator._deployment_admission_snapshot()
        self.assertEqual(total, snapshot["active_tool_calls"])
        self.assertEqual(total, snapshot["drain_blocking_tool_calls"])
        self.assertEqual(0, snapshot["read_only_active_tool_calls"])
        self.assertEqual("readOnlyHint-true-is-read-only-v1", snapshot["effect_classification"])
        self.assertEqual(
            {
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC: sync_count,
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC: async_count,
            },
            snapshot["active_tool_calls_by_kind"],
        )
        self.assertEqual(
            total, sum(snapshot["active_tool_calls_by_tool_name"].values())
        )
        self.assertFalse(snapshot["active_tool_calls_by_tool_name_truncated"])
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_NAME_GROUP_MAX,
            snapshot["active_tool_calls_by_tool_name_max"],
        )
        self.assertEqual(
            0, snapshot["active_tool_calls_by_tool_name_omitted_call_count"]
        )
        self.assertTrue(snapshot["active_tool_calls_sample_truncated"])
        self.assertEqual(limit, snapshot["active_tool_calls_sample_max"])
        self.assertEqual(limit, len(snapshot["active_tool_calls_sample"]))
        self.assertIsInstance(
            snapshot["oldest_active_tool_call_age_seconds"], float
        )
        self.assertGreaterEqual(snapshot["oldest_active_tool_call_age_seconds"], 0)
        for item in snapshot["active_tool_calls_sample"]:
            self.assertEqual(SAMPLE_ENTRY_KEYS, set(item))
            self.assertIsInstance(item["identity"], str)
            self.assertIn(item["kind"], snapshot["active_tool_calls_by_kind"])
            self.assertIsInstance(item["started_at_unix"], float)
            self.assertIsInstance(item["age_seconds"], float)
            self.assertGreaterEqual(item["age_seconds"], 0)

    def test_snapshot_tool_name_groups_are_bounded_and_account_for_omissions(
        self,
    ) -> None:
        operator = _load_operator_module()
        limit = operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_NAME_GROUP_MAX
        for index in range(limit + 3):
            operator._deployment_admission_register_tool_call(
                f"unique_{index:04d}",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
            )
        snapshot = operator._deployment_admission_snapshot()
        groups = snapshot["active_tool_calls_by_tool_name"]
        self.assertEqual(limit, len(groups))
        self.assertTrue(snapshot["active_tool_calls_by_tool_name_truncated"])
        self.assertEqual(limit, snapshot["active_tool_calls_by_tool_name_max"])
        self.assertEqual(
            3, snapshot["active_tool_calls_by_tool_name_omitted_call_count"]
        )
        self.assertEqual(limit, sum(groups.values()))

    def test_snapshot_empty_registry_has_stable_nullable_diagnostics(self) -> None:
        operator = _load_operator_module()
        snapshot = operator._deployment_admission_snapshot()
        self.assertEqual(0, snapshot["active_tool_calls"])
        self.assertEqual(0, snapshot["drain_blocking_tool_calls"])
        self.assertEqual(0, snapshot["read_only_active_tool_calls"])
        self.assertEqual("readOnlyHint-true-is-read-only-v1", snapshot["effect_classification"])
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX,
            snapshot["active_tool_call_registry_max"],
        )
        self.assertIsNone(snapshot["oldest_active_tool_call_age_seconds"])
        self.assertEqual({}, snapshot["active_tool_calls_by_kind"])
        self.assertEqual({}, snapshot["active_tool_calls_by_tool_name"])
        self.assertFalse(snapshot["active_tool_calls_by_tool_name_truncated"])
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_NAME_GROUP_MAX,
            snapshot["active_tool_calls_by_tool_name_max"],
        )
        self.assertEqual(
            0, snapshot["active_tool_calls_by_tool_name_omitted_call_count"]
        )
        self.assertEqual([], snapshot["active_tool_calls_sample"])
        self.assertFalse(snapshot["active_tool_calls_sample_truncated"])
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_SAMPLE_MAX,
            snapshot["active_tool_calls_sample_max"],
        )
        json.dumps(snapshot)

    def test_oldest_age_tracks_longest_running_call(self) -> None:
        operator = _load_operator_module()
        operator._deployment_admission_register_tool_call(
            "older", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
        )
        time.sleep(0.02)
        operator._deployment_admission_register_tool_call(
            "newer", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        snapshot = operator._deployment_admission_snapshot()
        self.assertGreaterEqual(
            snapshot["oldest_active_tool_call_age_seconds"], 0.01
        )
        oldest = snapshot["active_tool_calls_sample"][0]
        self.assertEqual("older", oldest["tool_name"])


class DeploymentAdmissionGateTests(unittest.TestCase):
    def test_gate_sync_tool_success_releases_by_identity(self) -> None:
        operator = _load_operator_module()
        caller_thread = threading.get_ident()
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()
        result = asyncio.run(operator.mcp._tool_manager.call_tool("read", {}))
        self.assertTrue(result["called"])
        self.assertNotEqual(caller_thread, result["thread_id"])
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_sync_tool_exception_releases_by_identity(self) -> None:
        operator = _load_operator_module()

        async def failing(*args, **kwargs):
            raise RuntimeError("sync failure")

        operator.mcp._tool_manager.call_tool = failing
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()
        with self.assertRaisesRegex(RuntimeError, "sync failure"):
            asyncio.run(operator.mcp._tool_manager.call_tool("read", {}))
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_sync_detached_pipe_holder_cannot_orphan_admission_identity(self) -> None:
        operator = _load_operator_module()
        script = (
            "import os,time\n"
            "pid=os.fork()\n"
            "if pid: os._exit(0)\n"
            "os.setsid()\n"
            "while True:\n"
            "    try: os.write(1,b'x')\n"
            "    except OSError: os._exit(0)\n"
            "    time.sleep(0.02)\n"
        )

        async def detached_pipe_call(*args, **kwargs):
            return operator._run(
                [operator.sys.executable, "-c", script],
                cwd=Path(tempfile.gettempdir()),
                timeout_seconds=1,
                max_output_bytes=1024,
            )

        operator.mcp._tool_manager.call_tool = detached_pipe_call
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg=None,
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        started = time.monotonic()
        with patch.object(
            operator, "PROCESS_TERMINATION_GRACE_SECONDS", 0.1
        ), patch.object(
            operator, "_require_transport_roundtrip_for_tool", return_value=None
        ):
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "grabowski_terminal_run", {}
                )
            )
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertTrue(result["timed_out"])
        self.assertEqual(0, result["returncode"])
        self.assertEqual(
            0, operator._deployment_admission_active_tool_calls()
        )
        snapshot = operator._deployment_admission_snapshot()
        self.assertEqual(0, snapshot["drain_blocking_tool_calls"])
        self.assertEqual([], snapshot["active_tool_calls_sample"])

    def test_gate_async_tool_success_and_exception_release_by_identity(self) -> None:
        operator = _load_operator_module()

        async def flaky(*args, **kwargs):
            arguments = args[1] if len(args) > 1 else kwargs.get("arguments") or {}
            if arguments.get("fail"):
                raise ValueError("async failure")
            return {"called": True}

        operator.mcp._tool_manager.call_tool = flaky
        operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
        operator._configure_http_runtime()
        result = asyncio.run(operator.mcp._tool_manager.call_tool("read", {}))
        self.assertTrue(result["called"])
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())
        with self.assertRaisesRegex(ValueError, "async failure"):
            asyncio.run(
                operator.mcp._tool_manager.call_tool("read", {"fail": True})
            )
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_async_tool_cancellation_releases_by_identity(self) -> None:
        operator = _load_operator_module()

        async def endless(*args, **kwargs):
            while True:
                await asyncio.sleep(0.01)

        operator.mcp._tool_manager.call_tool = endless
        operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
        operator._configure_http_runtime()

        async def exercise() -> None:
            call = asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {})
            )
            await asyncio.sleep(0.05)
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            snapshot = operator._deployment_admission_snapshot()
            self.assertEqual(
                {operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC: 1},
                snapshot["active_tool_calls_by_kind"],
            )
            self.assertEqual(0, snapshot["drain_blocking_tool_calls"])
            self.assertEqual(1, snapshot["read_only_active_tool_calls"])
            self.assertFalse(snapshot["active_tool_calls_sample"][0]["drain_blocking"])
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await call
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

        asyncio.run(exercise())

    def test_gate_sync_cancellation_keeps_identity_until_worker_finishes(
        self,
    ) -> None:
        operator = _load_operator_module()
        started = threading.Event()
        release = threading.Event()

        async def slow_call_tool(*args, **kwargs):
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test worker release timed out")
            return {"called": True}

        operator.mcp._tool_manager.call_tool = slow_call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()

        async def exercise() -> None:
            call = asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {})
            )
            started_ok = await asyncio.to_thread(started.wait, 2)
            self.assertTrue(started_ok)
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            snapshot = operator._deployment_admission_snapshot()
            self.assertEqual(
                {operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC: 1},
                snapshot["active_tool_calls_by_kind"],
            )
            self.assertEqual(
                {"read": 1}, snapshot["active_tool_calls_by_tool_name"]
            )
            self.assertEqual(0, snapshot["drain_blocking_tool_calls"])
            self.assertEqual(1, snapshot["read_only_active_tool_calls"])
            self.assertFalse(snapshot["active_tool_calls_sample"][0]["drain_blocking"])
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await call
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            release.set()
            for _attempt in range(200):
                if operator._deployment_admission_active_tool_calls() == 0:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

        asyncio.run(exercise())

    def test_gate_cancelled_queued_sync_tool_releases_never_run_identity(
        self,
    ) -> None:
        operator = _load_operator_module()
        started = threading.Event()
        release = threading.Event()
        executed: list[int] = []
        executor = ThreadPoolExecutor(max_workers=1)
        operator._SYNC_TOOL_EXECUTOR = executor

        async def slow_call_tool(_name, arguments):
            executed.append(arguments["slot"])
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test worker release timed out")
            return {"called": True, "slot": arguments["slot"]}

        operator.mcp._tool_manager.call_tool = slow_call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()

        async def exercise() -> None:
            running = asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {"slot": 1})
            )
            started_ok = await asyncio.to_thread(started.wait, 2)
            self.assertTrue(started_ok)
            queued = asyncio.create_task(
                operator.mcp._tool_manager.call_tool("read", {"slot": 2})
            )
            await asyncio.sleep(0)
            self.assertEqual(2, operator._deployment_admission_active_tool_calls())
            queued.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await queued
            self.assertEqual(1, operator._deployment_admission_active_tool_calls())
            release.set()
            self.assertEqual(1, (await running)["slot"])
            for _attempt in range(200):
                if operator._deployment_admission_active_tool_calls() == 0:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())
            self.assertEqual([1], executed)

        try:
            asyncio.run(exercise())
        finally:
            release.set()
            executor.shutdown(wait=True, cancel_futures=True)

    def test_gate_submission_failure_releases_identity(self) -> None:
        operator = _load_operator_module()

        class RejectingExecutor:
            def submit(self, *args, **kwargs):
                raise RuntimeError("executor rejected")

        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._SYNC_TOOL_EXECUTOR = RejectingExecutor()
        operator._configure_http_runtime()
        with self.assertRaisesRegex(RuntimeError, "executor rejected"):
            asyncio.run(operator.mcp._tool_manager.call_tool("read", {}))
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_registry_capacity_rejects_before_original_effect(self) -> None:
        operator = _load_operator_module()
        calls: list[str] = []

        async def original(*args, **kwargs):
            calls.append("executed")
            return {"called": True}

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
        operator._configure_http_runtime()
        with patch.object(
            operator, "_DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX", 0
        ):
            with self.assertRaisesRegex(RuntimeError, "registry is full"):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}))
        self.assertEqual([], calls)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_registers_before_decisive_marker_read(self) -> None:
        operator = _load_operator_module()
        calls: list[str] = []

        async def original(*args, **kwargs):
            calls.append("executed")
            return {"called": True}

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
        operator._configure_http_runtime()
        absent = {"state": "absent", "active": False, "valid": False}
        active = {"state": "active", "active": True, "valid": True}
        with patch.object(
            operator,
            "_read_deployment_admission_marker",
            side_effect=[absent, active],
        ):
            with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}))
        self.assertEqual([], calls)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_revalidates_observer_exemption_against_current_marker(self) -> None:
        operator = _load_operator_module()
        marker = {"state": "active", "active": True, "valid": True}
        with patch.object(
            operator,
            "_read_deployment_admission_marker",
            side_effect=[marker, marker, marker],
        ), patch.object(
            operator,
            "_deployment_observer_request_evidence",
            side_effect=[{"marker_bound": True}, None],
        ):
            operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
            operator._configure_http_runtime()
            with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        operator.deployment_observer.OPERATION, {}
                    )
                )
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_rejects_non_observer_call_while_marker_active(self) -> None:
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
                    asyncio.run(
                        operator.mcp._tool_manager.call_tool("write", {})
                    )
                self.assertEqual(
                    0, operator._deployment_admission_active_tool_calls()
                )
                snapshot = operator._deployment_admission_snapshot()
                self.assertEqual(0, snapshot["active_tool_calls"])
                self.assertFalse(snapshot["active_tool_calls_sample_truncated"])

    def test_gate_marker_bound_observer_call_is_drain_neutral(self) -> None:
        operator = _load_operator_module()
        marker = {
            "kind": "grabowski_deployment_admission_observation",
            "state": "active",
            "active": True,
            "valid": True,
        }
        with patch.object(
            operator,
            "_read_deployment_admission_marker",
            return_value=marker,
        ), patch.object(
            operator,
            "_deployment_observer_request_evidence",
            return_value={"marker_bound": True},
        ):
            operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
            operator._configure_http_runtime()
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    operator.deployment_observer.OPERATION, {}
                )
            )
            self.assertTrue(result["called"])
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_snapshot_never_exposes_tool_arguments(self) -> None:
        operator = _load_operator_module()
        started = threading.Event()
        release = threading.Event()

        async def slow_call_tool(*args, **kwargs):
            started.set()
            if not release.wait(timeout=5):
                raise RuntimeError("test worker release timed out")
            return {"called": True}

        operator.mcp._tool_manager.call_tool = slow_call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()

        async def exercise() -> None:
            call = asyncio.create_task(
                operator.mcp._tool_manager.call_tool(
                    "read", {"secret": "top-secret", "arguments": ["unbounded"]}
                )
            )
            started_ok = await asyncio.to_thread(started.wait, 2)
            self.assertTrue(started_ok)
            snapshot = operator._deployment_admission_snapshot()
            for item in snapshot["active_tool_calls_sample"]:
                self.assertEqual(SAMPLE_ENTRY_KEYS, set(item))
            payload = json.dumps(snapshot)
            self.assertNotIn("top-secret", payload)
            self.assertNotIn("unbounded", payload)
            release.set()
            await call

        try:
            asyncio.run(exercise())
        finally:
            release.set()

    def test_gate_concurrent_distinct_calls_are_identity_bound(self) -> None:
        operator = _load_operator_module()
        started = threading.Barrier(3)
        release = threading.Event()

        async def gated(*args, **kwargs):
            started.wait(timeout=5)
            if not release.wait(timeout=5):
                raise RuntimeError("test worker release timed out")
            return {"called": True, "slot": args[1]}

        operator.mcp._tool_manager.call_tool = gated
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()

        async def run_one(slot: int):
            return await operator.mcp._tool_manager.call_tool("read", slot)

        async def exercise() -> None:
            tasks = [asyncio.create_task(run_one(slot)) for slot in range(3)]
            for _attempt in range(200):
                if operator._deployment_admission_active_tool_calls() == 3:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(3, operator._deployment_admission_active_tool_calls())
            snapshot = operator._deployment_admission_snapshot()
            identities = [
                item["identity"]
                for item in snapshot["active_tool_calls_sample"]
            ]
            self.assertEqual(3, len(set(identities)))
            self.assertEqual(
                {operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC: 3},
                snapshot["active_tool_calls_by_kind"],
            )
            self.assertEqual(
                {"read": 3}, snapshot["active_tool_calls_by_tool_name"]
            )
            release.set()
            results = await asyncio.gather(*tasks)
            self.assertEqual({0, 1, 2}, {item["slot"] for item in results})
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

        try:
            asyncio.run(exercise())
        finally:
            release.set()


if __name__ == "__main__":
    unittest.main()

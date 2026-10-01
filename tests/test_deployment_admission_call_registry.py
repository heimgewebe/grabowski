from __future__ import annotations

import asyncio
import io
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

    def test_drain_neutral_reserve_preserves_probe_capacity_at_blocking_limit(
        self,
    ) -> None:
        operator = _load_operator_module()
        with patch.object(
            operator, "_DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX", 2
        ), patch.object(
            operator, "_DEPLOYMENT_ADMISSION_DRAIN_NEUTRAL_RESERVE", 1
        ):
            first = operator._deployment_admission_register_tool_call(
                "first", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
            )
            second = operator._deployment_admission_register_tool_call(
                "second", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
            )
            observer = operator._deployment_admission_register_tool_call(
                "observer",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
                drain_blocking=False,
                drain_neutral=True,
            )
            snapshot = operator._deployment_admission_snapshot()
            self.assertEqual(3, snapshot["active_tool_calls"])
            self.assertEqual(2, snapshot["drain_blocking_tool_calls"])
            self.assertEqual(1, snapshot["read_only_active_tool_calls"])
            self.assertEqual(2, snapshot["active_tool_call_registry_max"])
            self.assertEqual(1, snapshot["drain_neutral_tool_call_reserve"])
            self.assertEqual(3, snapshot["active_tool_call_registry_hard_max"])

            with self.assertRaisesRegex(RuntimeError, "registry is full"):
                operator._deployment_admission_register_tool_call(
                    "second-observer",
                    operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
                    drain_blocking=False,
                    drain_neutral=True,
                )
            with self.assertRaisesRegex(RuntimeError, "registry is full"):
                operator._deployment_admission_register_tool_call(
                    "third-blocking",
                    operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
                )

            self.assertTrue(operator._deployment_admission_release_tool_call(first))
            with self.assertRaisesRegex(RuntimeError, "registry is full"):
                operator._deployment_admission_register_tool_call(
                    "replacement-before-observer-release",
                    operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
                )
            self.assertTrue(operator._deployment_admission_release_tool_call(observer))
            replacement = operator._deployment_admission_register_tool_call(
                "replacement",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
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

    def test_registry_rejects_invalid_drain_neutral_classification(self) -> None:
        operator = _load_operator_module()
        with self.assertRaisesRegex(ValueError, "drain_neutral must be boolean"):
            operator._deployment_admission_register_tool_call(
                "read",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
                drain_blocking=False,
                drain_neutral=1,
            )
        with self.assertRaisesRegex(
            ValueError, "drain_neutral calls must be drain_blocking=false"
        ):
            operator._deployment_admission_register_tool_call(
                "read",
                operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
                drain_neutral=True,
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
        self.assertEqual("readOnlyHint-or-server-verified-git-read-or-exact-github-pr-view-is-read-only-v3", snapshot["effect_classification"])
        self.assertEqual(
            "live_grabowski_operator_call_boundary",
            snapshot["registry_authority"],
        )
        self.assertEqual("draining", snapshot["effect_terminalization_state"])
        self.assertFalse(snapshot["read_calls_block_retirement"])
        self.assertRegex(snapshot["registry_observation_sha256"], r"^[0-9a-f]{64}$")
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
        self.assertEqual("readOnlyHint-or-server-verified-git-read-or-exact-github-pr-view-is-read-only-v3", snapshot["effect_classification"])
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX,
            snapshot["active_tool_call_registry_max"],
        )
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_DRAIN_NEUTRAL_RESERVE,
            snapshot["drain_neutral_tool_call_reserve"],
        )
        self.assertEqual(
            operator._DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX
            + operator._DEPLOYMENT_ADMISSION_DRAIN_NEUTRAL_RESERVE,
            snapshot["active_tool_call_registry_hard_max"],
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


class SyncToolAllocatorTrimTests(unittest.TestCase):
    def _libc(self, free_bytes: int, calls: list[int]):
        return types.SimpleNamespace(
            mallinfo2=lambda: types.SimpleNamespace(fordblks=free_bytes),
            malloc_trim=lambda pad: calls.append(pad) or 1,
        )

    def test_trim_waits_until_tool_registry_is_idle_and_retries_on_final_release(
        self,
    ) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        identity = operator._deployment_admission_register_tool_call(
            "busy-async", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", return_value=100.0
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", float("-inf")
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertEqual([], calls)
            self.assertTrue(operator._deployment_admission_release_tool_call(identity))
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertEqual([], calls)
            self.assertEqual(1, len(timers))
            self.assertEqual(0.0, timers[0].interval)

            timers[0].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)

    def test_trim_allows_drain_neutral_overlap(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        identity = operator._deployment_admission_register_tool_call(
            "read-only-overlap",
            operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
            drain_blocking=False,
            drain_neutral=True,
        )
        try:
            with patch.object(
                operator, "_sync_tool_allocator_libc", return_value=libc
            ), patch.object(
                operator.time, "monotonic", return_value=100.0
            ), patch.object(
                operator,
                "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC",
                float("-inf"),
            ):
                self.assertTrue(operator._maybe_trim_sync_tool_allocator())
                self.assertEqual([0], calls)
                self.assertEqual(
                    1, operator._deployment_admission_active_tool_calls()
                )
                self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        finally:
            operator._deployment_admission_release_tool_call(identity)

    def test_last_blocking_release_retries_with_drain_neutral_overlap(
        self,
    ) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.started = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        read_only_identity = operator._deployment_admission_register_tool_call(
            "read-only-overlap",
            operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
            drain_blocking=False,
            drain_neutral=True,
        )
        blocking_identity = operator._deployment_admission_register_tool_call(
            "blocking-work",
            operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC,
        )
        operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED = True
        try:
            with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
                operator, "_sync_tool_allocator_libc", return_value=libc
            ), patch.object(
                operator.time, "monotonic", return_value=200.0
            ), patch.object(
                operator,
                "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC",
                float("-inf"),
            ):
                self.assertTrue(
                    operator._deployment_admission_release_tool_call(
                        blocking_identity
                    )
                )
                self.assertEqual(
                    1, operator._deployment_admission_active_tool_calls()
                )
                self.assertEqual(1, len(timers))
                self.assertEqual(0.0, timers[0].interval)
                self.assertTrue(timers[0].daemon)
                self.assertTrue(timers[0].started)
                self.assertEqual([], calls)

                timers[0].fire()

            self.assertEqual([0], calls)
            self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        finally:
            operator._deployment_admission_release_tool_call(read_only_identity)

    def test_trim_requires_material_free_arena_bytes_and_respects_cooldown(
        self,
    ) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        below = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES - 1,
            calls,
        )
        enough = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        with patch.object(
            operator, "_sync_tool_allocator_libc", return_value=below
        ), patch.object(
            operator.time, "monotonic", return_value=100.0
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", float("-inf")
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
        self.assertEqual([], calls)

        with patch.object(
            operator, "_sync_tool_allocator_libc", return_value=enough
        ), patch.object(
            operator.time, "monotonic", side_effect=[100.0, 101.0, 131.0]
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", float("-inf")
        ), patch.object(
            operator, "_schedule_sync_tool_allocator_trim_retry"
        ) as schedule_retry:
            self.assertTrue(operator._maybe_trim_sync_tool_allocator())
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            schedule_retry.assert_called_once_with(29.0)
            self.assertTrue(operator._maybe_trim_sync_tool_allocator())
        self.assertEqual([0, 0], calls)

    def test_deferred_trim_retries_when_async_work_reaches_idle(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.started = False
                self.cancelled = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                self.cancelled = True

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        identity = operator._deployment_admission_register_tool_call(
            "async-work", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", return_value=200.0
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", float("-inf")
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertTrue(operator._deployment_admission_release_tool_call(identity))
            self.assertEqual([], calls)
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertEqual(1, len(timers))
            self.assertEqual(0.0, timers[0].interval)
            self.assertTrue(timers[0].daemon)
            self.assertTrue(timers[0].started)

            timers[0].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_trim_cooldown_defers_until_a_later_idle_release(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.started = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        monotonic = [101.0]
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", side_effect=lambda: monotonic[0]
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", 100.0
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertEqual(1, len(timers))
            self.assertEqual(29.0, timers[0].interval)
            self.assertEqual([], calls)

            identity = operator._deployment_admission_register_tool_call(
                "later-async", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
            )
            monotonic[0] = 131.0
            self.assertTrue(operator._deployment_admission_release_tool_call(identity))
            self.assertEqual(1, len(timers))
            self.assertEqual([], calls)
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)

            timers[0].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)

    def test_trim_cooldown_retry_runs_without_a_later_tool_release(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.started = False
                self.cancelled = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                self.cancelled = True

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        monotonic = [101.0]
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", side_effect=lambda: monotonic[0]
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", 100.0
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            self.assertEqual(1, len(timers))
            timer = timers[0]
            self.assertEqual(29.0, timer.interval)
            self.assertTrue(timer.daemon)
            self.assertTrue(timer.started)
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)

            monotonic[0] = 130.0
            timer.fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_trim_cooldown_retry_rechecks_global_idle(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        monotonic = [101.0]
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", side_effect=lambda: monotonic[0]
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", 100.0
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            identity = operator._deployment_admission_register_tool_call(
                "still-active", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
            )
            monotonic[0] = 130.0
            timers[0].fire()
            self.assertEqual([], calls)
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertTrue(operator._deployment_admission_release_tool_call(identity))
            self.assertEqual(2, len(timers))
            self.assertEqual(0.0, timers[1].interval)
            self.assertEqual([], calls)

            timers[1].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)

    def test_trim_cooldown_retry_is_coalesced_and_stale_callback_is_ignored(
        self,
    ) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.function = function
                self.args = args
                self.daemon = False
                self.cancelled = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                self.cancelled = True

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        monotonic = [101.0]
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", side_effect=lambda: monotonic[0]
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", 100.0
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            monotonic[0] = 102.0
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())
            self.assertEqual(1, len(timers))

            monotonic[0] = 131.0
            self.assertTrue(operator._maybe_trim_sync_tool_allocator())
            self.assertTrue(timers[0].cancelled)
            timers[0].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_trim_cooldown_retry_requested_in_flight_is_coalesced(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.cancelled = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                self.cancelled = True

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        monotonic = [101.0]
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", side_effect=lambda: monotonic[0]
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", 100.0
        ):
            self.assertTrue(operator._schedule_sync_tool_allocator_trim_retry(0.0))
            self.assertEqual(1, len(timers))

            timers[0].fire()

            self.assertEqual([], calls)
            self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)
            self.assertIsNone(
                operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_COALESCED_DELAY_SECONDS
            )
            self.assertEqual(2, len(timers))
            self.assertEqual(29.0, timers[1].interval)
            self.assertIs(
                timers[1],
                operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER,
            )

            monotonic[0] = 130.0
            timers[1].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)
        self.assertIsNone(
            operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_COALESCED_DELAY_SECONDS
        )
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_trim_retry_stale_callback_cannot_clear_replacement(self) -> None:
        operator = _load_operator_module()
        timers: list[object] = []
        attempts: list[int] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.cancelled = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                self.cancelled = True

            def fire(self):
                self.function(*self.args)

        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator,
            "_maybe_trim_sync_tool_allocator",
            side_effect=lambda: attempts.append(threading.get_ident()) or False,
        ):
            self.assertTrue(operator._schedule_sync_tool_allocator_trim_retry(10.0))
            stale_timer = timers[0]
            operator._cancel_sync_tool_allocator_trim_retry()
            self.assertTrue(stale_timer.cancelled)

            self.assertTrue(operator._schedule_sync_tool_allocator_trim_retry(20.0))
            replacement = timers[1]
            stale_timer.fire()

            self.assertEqual([], attempts)
            self.assertIs(
                replacement,
                operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER,
            )
            self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)

            replacement.fire()

        self.assertEqual(1, len(attempts))
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)
        self.assertIsNone(
            operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_COALESCED_DELAY_SECONDS
        )

    def test_final_async_release_does_not_wait_for_in_progress_trim_gate(
        self,
    ) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.started = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        identity = operator._deployment_admission_register_tool_call(
            "last-active", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_ASYNC
        )
        operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED = True
        operator._SYNC_TOOL_ALLOCATOR_TRIM_LOCK.acquire()
        done = threading.Event()
        released: list[bool] = []

        def release_last() -> None:
            try:
                released.append(
                    operator._deployment_admission_release_tool_call(identity)
                )
            finally:
                done.set()

        thread = threading.Thread(target=release_last, daemon=True)
        try:
            with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
                operator, "_sync_tool_allocator_libc", return_value=libc
            ), patch.object(
                operator.time, "monotonic", return_value=200.0
            ), patch.object(
                operator,
                "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC",
                float("-inf"),
            ):
                thread.start()
                self.assertTrue(done.wait(timeout=1.0))
                thread.join(timeout=1.0)
                self.assertEqual([True], released)
                self.assertEqual(
                    0, operator._deployment_admission_active_tool_calls()
                )
                self.assertEqual([], calls)
                self.assertEqual(1, len(timers))
                self.assertEqual(0.0, timers[0].interval)
                self.assertTrue(timers[0].daemon)
                self.assertTrue(timers[0].started)
                self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)

                operator._SYNC_TOOL_ALLOCATOR_TRIM_LOCK.release()
                timers[0].fire()
        finally:
            if operator._SYNC_TOOL_ALLOCATOR_TRIM_LOCK.locked():
                operator._SYNC_TOOL_ALLOCATOR_TRIM_LOCK.release()
            thread.join(timeout=1.0)

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_final_undispatched_sync_release_schedules_deferred_retry(self) -> None:
        operator = _load_operator_module()
        calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                self.started = False
                timers.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        libc = self._libc(
            operator.SYNC_TOOL_ALLOCATOR_TRIM_FREE_BYTES,
            calls,
        )
        identity = operator._deployment_admission_register_tool_call(
            "undispatched-sync",
            operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC,
        )
        operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED = True
        with patch.object(operator.threading, "Timer", FakeTimer), patch.object(
            operator, "_sync_tool_allocator_libc", return_value=libc
        ), patch.object(
            operator.time, "monotonic", return_value=200.0
        ), patch.object(
            operator,
            "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC",
            float("-inf"),
        ):
            self.assertTrue(operator._deployment_admission_release_tool_call(identity))
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())
            self.assertEqual([], calls)
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
            self.assertEqual(1, len(timers))
            self.assertEqual(0.0, timers[0].interval)
            self.assertTrue(timers[0].daemon)
            self.assertTrue(timers[0].started)

            timers[0].fire()

        self.assertEqual([0], calls)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_DEFERRED)
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_trim_is_fail_soft_when_glibc_allocator_api_is_unavailable(self) -> None:
        operator = _load_operator_module()
        with patch.object(
            operator, "_sync_tool_allocator_libc", return_value=None
        ), patch.object(
            operator.time, "monotonic", return_value=100.0
        ), patch.object(
            operator, "_SYNC_TOOL_ALLOCATOR_TRIM_LAST_MONOTONIC", float("-inf")
        ):
            self.assertFalse(operator._maybe_trim_sync_tool_allocator())


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

    def test_gate_sync_allocator_trim_is_scheduled_after_admission_release(
        self,
    ) -> None:
        operator = _load_operator_module()
        scheduled: list[tuple[float, int]] = []

        def observe_schedule(delay_seconds: float) -> bool:
            scheduled.append(
                (
                    delay_seconds,
                    operator._deployment_admission_active_tool_calls(),
                )
            )
            return True

        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator,
            "_schedule_sync_tool_allocator_trim_retry",
            side_effect=observe_schedule,
        ):
            operator._configure_http_runtime()
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool("read", {})
            )

        self.assertTrue(result["called"])
        self.assertEqual([(0.0, 0)], scheduled)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_sync_already_done_callback_never_trims_inline(self) -> None:
        operator = _load_operator_module()
        worker_future = operator.concurrent.futures.Future()
        worker_future.set_result({"called": True})
        timers: list[object] = []
        trim_threads: list[str] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator, "_submit_sync_tool_call", return_value=worker_future
        ), patch.object(
            operator.threading, "Timer", FakeTimer
        ), patch.object(
            operator,
            "_maybe_trim_sync_tool_allocator",
            side_effect=lambda: trim_threads.append(threading.current_thread().name)
            or False,
        ):
            operator._configure_http_runtime()
            started = time.perf_counter()
            result = asyncio.run(operator.mcp._tool_manager.call_tool("read", {}))
            elapsed = time.perf_counter() - started

            self.assertTrue(result["called"])
            self.assertLess(elapsed, 0.1)
            self.assertEqual([], trim_threads)
            self.assertEqual(1, len(timers))
            self.assertEqual(0.0, timers[0].interval)
            self.assertTrue(timers[0].daemon)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

            timers[0].fire()

        self.assertEqual(1, len(trim_threads))
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_sync_completion_burst_coalesces_while_retry_is_in_flight(
        self,
    ) -> None:
        operator = _load_operator_module()
        timers: list[object] = []
        attempt_entered = threading.Event()
        release_attempt = threading.Event()
        attempts: list[int] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        def completed_future(*_args, **_kwargs):
            future = operator.concurrent.futures.Future()
            future.set_result({"called": True})
            return future

        def blocked_trim_attempt() -> bool:
            attempts.append(threading.get_ident())
            attempt_entered.set()
            self.assertTrue(release_attempt.wait(timeout=2.0))
            return False

        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator, "_submit_sync_tool_call", side_effect=completed_future
        ), patch.object(
            operator.threading, "Timer", FakeTimer
        ), patch.object(
            operator,
            "_maybe_trim_sync_tool_allocator",
            side_effect=blocked_trim_attempt,
        ):
            operator._configure_http_runtime()
            first = asyncio.run(operator.mcp._tool_manager.call_tool("read", {}))
            self.assertTrue(first["called"])
            self.assertEqual(1, len(timers))

            retry_thread = threading.Thread(
                target=timers[0].fire,
                daemon=True,
            )
            retry_thread.start()
            self.assertTrue(attempt_entered.wait(timeout=1.0))
            self.assertTrue(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)

            started = time.perf_counter()
            for _ in range(32):
                result = asyncio.run(
                    operator.mcp._tool_manager.call_tool("read", {})
                )
                self.assertTrue(result["called"])
            elapsed = time.perf_counter() - started

            self.assertLess(elapsed, 1.0)
            self.assertEqual(1, len(timers))
            self.assertEqual(
                0.0,
                operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_COALESCED_DELAY_SECONDS,
            )
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

            release_attempt.set()
            retry_thread.join(timeout=1.0)
            self.assertFalse(retry_thread.is_alive())

            self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)
            self.assertIsNone(
                operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_COALESCED_DELAY_SECONDS
            )
            self.assertEqual(2, len(timers))
            self.assertIs(
                timers[1],
                operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER,
            )

            timers[1].fire()

        self.assertEqual(2, len(attempts))
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)
        self.assertFalse(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_IN_FLIGHT)
        self.assertIsNone(
            operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_COALESCED_DELAY_SECONDS
        )
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_concurrent_sync_status_calls_use_single_worker_status_lane(self) -> None:
        operator = _load_operator_module()
        state_lock = threading.Lock()
        active = 0
        peak_active = 0

        async def status_call(name, _arguments, *args, **kwargs):
            nonlocal active, peak_active
            self.assertEqual("grabowski_status", name)
            with state_lock:
                active += 1
                peak_active = max(peak_active, active)
            try:
                await asyncio.sleep(0.03)
                return {"called": True}
            finally:
                with state_lock:
                    active -= 1

        operator.mcp._tool_manager.call_tool = status_call
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator, "_maybe_trim_sync_tool_allocator", return_value=False
        ):
            operator._configure_http_runtime()

            async def exercise() -> list[dict[str, bool]]:
                return await asyncio.gather(
                    *[
                        operator.mcp._tool_manager.call_tool(
                            "grabowski_status", {"view": "minimal"}
                        )
                        for _ in range(3)
                    ]
                )

            results = asyncio.run(exercise())

        self.assertEqual([{"called": True}] * 3, results)
        self.assertEqual(1, peak_active)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_status_backlog_does_not_starve_regular_sync_tool(self) -> None:
        operator = _load_operator_module()
        status_started = threading.Event()
        status_release = threading.Event()
        regular_ran = threading.Event()
        shared_executor = ThreadPoolExecutor(max_workers=1)
        status_executor = ThreadPoolExecutor(max_workers=1)

        async def call_tool(name, _arguments, *args, **kwargs):
            if name == "grabowski_status":
                status_started.set()
                if not status_release.wait(timeout=5):
                    raise RuntimeError("status release timed out")
                return {"called": True, "name": name}
            regular_ran.set()
            return {"called": True, "name": name}

        operator.mcp._tool_manager.call_tool = call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._SYNC_TOOL_EXECUTOR = shared_executor
        operator._SYNC_TOOL_STATUS_EXECUTOR = status_executor
        with patch.object(
            operator, "_maybe_trim_sync_tool_allocator", return_value=False
        ):
            operator._configure_http_runtime()

            async def exercise() -> None:
                statuses = [
                    asyncio.create_task(
                        operator.mcp._tool_manager.call_tool(
                            "grabowski_status", {"view": "minimal"}
                        )
                    )
                    for _ in range(8)
                ]
                started = await asyncio.to_thread(status_started.wait, 2)
                self.assertTrue(started)
                regular = await asyncio.wait_for(
                    operator.mcp._tool_manager.call_tool("read", {}),
                    timeout=1,
                )
                self.assertEqual({"called": True, "name": "read"}, regular)
                self.assertTrue(regular_ran.is_set())
                status_release.set()
                results = await asyncio.gather(*statuses)
                self.assertEqual(8, len(results))

            try:
                asyncio.run(exercise())
            finally:
                status_release.set()
                shared_executor.shutdown(wait=True, cancel_futures=True)
                status_executor.shutdown(wait=True, cancel_futures=True)

        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_drain_neutral_sync_status_bypasses_status_backlog(self) -> None:
        operator = _load_operator_module()
        status_started = threading.Event()
        status_release = threading.Event()
        readiness_ran = threading.Event()
        status_executor = ThreadPoolExecutor(max_workers=1)
        readiness_status_executor = ThreadPoolExecutor(max_workers=1)
        marker_active = [False]
        call_lock = threading.Lock()
        status_call_count = 0

        async def call_tool(name, _arguments, *args, **kwargs):
            nonlocal status_call_count
            self.assertEqual("grabowski_status", name)
            with call_lock:
                status_call_count += 1
                call_number = status_call_count
            if call_number == 1:
                status_started.set()
                if not status_release.wait(timeout=5):
                    raise RuntimeError("status release timed out")
            elif marker_active[0]:
                readiness_ran.set()
            return {"called": True, "call_number": call_number}

        def marker():
            if marker_active[0]:
                return {"state": "active", "active": True, "valid": True}
            return {"state": "absent", "active": False, "valid": False}

        operator.mcp._tool_manager.call_tool = call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._SYNC_TOOL_STATUS_EXECUTOR = status_executor
        operator._SYNC_TOOL_DRAIN_NEUTRAL_STATUS_EXECUTOR = readiness_status_executor
        with patch.object(
            operator, "_read_deployment_admission_marker", side_effect=marker
        ), patch.object(
            operator, "_schedule_sync_tool_allocator_trim_retry", return_value=True
        ):
            operator._configure_http_runtime()

            async def exercise() -> None:
                ordinary = [
                    asyncio.create_task(
                        operator.mcp._tool_manager.call_tool(
                            "grabowski_status", {"view": "minimal"}
                        )
                    )
                    for _ in range(2)
                ]
                started = await asyncio.to_thread(status_started.wait, 2)
                self.assertTrue(started)
                for _attempt in range(100):
                    if operator._deployment_admission_active_tool_calls() == 2:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(
                    2, operator._deployment_admission_active_tool_calls()
                )

                marker_active[0] = True
                readiness = await asyncio.wait_for(
                    operator.mcp._tool_manager.call_tool(
                        "grabowski_status", {"view": "minimal"}
                    ),
                    timeout=1,
                )
                self.assertTrue(readiness["called"])
                self.assertTrue(readiness_ran.is_set())
                self.assertFalse(status_release.is_set())

                marker_active[0] = False
                status_release.set()
                results = await asyncio.gather(*ordinary)
                self.assertEqual(2, len(results))

            try:
                asyncio.run(exercise())
            finally:
                status_release.set()
                status_executor.shutdown(wait=True, cancel_futures=True)
                readiness_status_executor.shutdown(wait=True, cancel_futures=True)

        self.assertEqual(3, status_call_count)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_drain_neutral_status_calls_remain_serialized(self) -> None:
        operator = _load_operator_module()
        state_lock = threading.Lock()
        active = 0
        peak_active = 0
        readiness_status_executor = ThreadPoolExecutor(max_workers=1)
        marker = {"state": "active", "active": True, "valid": True}

        async def status_call(name, _arguments, *args, **kwargs):
            nonlocal active, peak_active
            self.assertEqual("grabowski_status", name)
            with state_lock:
                active += 1
                peak_active = max(peak_active, active)
            try:
                await asyncio.sleep(0.03)
                return {"called": True}
            finally:
                with state_lock:
                    active -= 1

        operator.mcp._tool_manager.call_tool = status_call
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._SYNC_TOOL_DRAIN_NEUTRAL_STATUS_EXECUTOR = (
            readiness_status_executor
        )
        with patch.object(
            operator, "_read_deployment_admission_marker", return_value=marker
        ), patch.object(
            operator, "_schedule_sync_tool_allocator_trim_retry", return_value=True
        ):
            operator._configure_http_runtime()

            async def exercise() -> list[dict[str, bool]]:
                return await asyncio.gather(
                    *[
                        operator.mcp._tool_manager.call_tool(
                            "grabowski_status", {"view": "minimal"}
                        )
                        for _ in range(3)
                    ]
                )

            try:
                results = asyncio.run(exercise())
            finally:
                readiness_status_executor.shutdown(
                    wait=True, cancel_futures=True
                )

        self.assertEqual([{"called": True}] * 3, results)
        self.assertEqual(1, peak_active)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_sync_repoground_consultation_logs_only_tool_name(self) -> None:
        operator = _load_operator_module()
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()
        arguments = {
            "repo": "private-repository-name",
            "query": "private query contents",
        }

        with patch.object(operator.logging, "getLogger", side_effect=AssertionError(
            "consultation telemetry must not depend on Python logger configuration"
        )), patch.object(operator.sys, "stderr", io.StringIO()) as captured:
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "repoground_context_pack",
                    arguments,
                )
            )

        self.assertTrue(result["called"])
        output = captured.getvalue()
        self.assertIn(
            "repoground-consultation-completed "
            "tool=repoground_context_pack "
            "source=mcp-tool-boundary arguments_logged=false outcome=success",
            output,
        )
        self.assertNotIn("private-repository-name", output)
        self.assertNotIn("private query contents", output)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_async_repoground_consultation_is_recorded_after_success(self) -> None:
        operator = _load_operator_module()

        async def called(*args, **kwargs):
            return {"called": True}

        operator.mcp._tool_manager.call_tool = called
        operator.mcp._tool_manager.get_tool = lambda _name: _async_tool()
        operator._configure_http_runtime()

        with patch.object(operator.sys, "stderr", io.StringIO()) as captured:
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "repoground_query",
                    {"repo": "private", "query": "private"},
                )
            )

        self.assertTrue(result["called"])
        output = captured.getvalue()
        self.assertIn(
            "repoground-consultation-completed "
            "tool=repoground_query "
            "source=mcp-tool-boundary arguments_logged=false outcome=success",
            output,
        )
        self.assertNotIn("repo=private", output)
        self.assertNotIn("query=private", output)

    def test_repoground_consultation_telemetry_is_best_effort(self) -> None:
        operator = _load_operator_module()

        class BrokenStderr:
            def write(self, _text):
                raise OSError("journal unavailable")

            def flush(self):
                raise OSError("journal unavailable")

        with patch.object(operator.sys, "stderr", BrokenStderr()):
            operator._record_repoground_consultation("repoground_query")

    def test_repoground_consultation_ignores_non_repoground_tools(self) -> None:
        operator = _load_operator_module()
        with patch.object(operator.sys, "stderr", io.StringIO()) as captured:
            operator._record_repoground_consultation("grabowski_read_text")
        self.assertEqual("", captured.getvalue())

    def test_gate_rejected_repoground_call_is_not_recorded_as_consultation(
        self,
    ) -> None:
        operator = _load_operator_module()
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator.base,
            "_transport_authorize_connector_tool",
            side_effect=RuntimeError("connector rejected"),
        ), patch.object(
            operator, "_record_repoground_consultation"
        ) as record:
            operator._configure_http_runtime()
            with self.assertRaisesRegex(RuntimeError, "connector rejected"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "repoground_context_pack",
                        {"repo": "private"},
                    )
                )
        record.assert_not_called()

    def test_gate_schema_rejected_repoground_call_is_not_recorded_as_consultation(
        self,
    ) -> None:
        operator = _load_operator_module()
        domain_started = False

        async def schema_validating_call(name, arguments, *args, **kwargs):
            nonlocal domain_started
            if (
                name != "repoground_context_pack"
                or set(arguments) != {"repo"}
                or not isinstance(arguments.get("repo"), str)
            ):
                raise ValueError("schema-rejected")
            domain_started = True
            return {"called": True}

        operator.mcp._tool_manager.call_tool = schema_validating_call
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._configure_http_runtime()

        with patch.object(
            operator, "_record_repoground_consultation"
        ) as record:
            with self.assertRaisesRegex(ValueError, "schema-rejected"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "repoground_context_pack",
                        {"unexpected": "schema-rejected"},
                    )
                )

        self.assertFalse(domain_started)
        record.assert_not_called()

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

    def test_gate_sync_same_group_survivor_is_killed_after_leader_exits(self) -> None:
        operator = _load_operator_module()
        marker = Path(tempfile.gettempdir()) / f"grabowski-child-{time.time_ns()}.pid"
        heartbeat = marker.with_suffix(".heartbeat")
        script = (
            "import os,signal,sys,time\n"
            "marker,heartbeat=sys.argv[1:3]\n"
            "pid=os.fork()\n"
            "if pid:\n"
            "    while True: time.sleep(1)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "with open(marker,'w',encoding='ascii') as handle: handle.write(str(os.getpid()))\n"
            "with open(heartbeat,'ab',buffering=0) as handle:\n"
            "    while True:\n"
            "        handle.write(b'x')\n"
            "        time.sleep(0.02)\n"
        )

        async def same_group_survivor(*args, **kwargs):
            return operator._run(
                [operator.sys.executable, "-c", script, str(marker), str(heartbeat)],
                cwd=Path(tempfile.gettempdir()),
                timeout_seconds=1,
                max_output_bytes=1024,
            )

        operator.mcp._tool_manager.call_tool = same_group_survivor
        operator.mcp._tool_manager.get_tool = lambda _name: types.SimpleNamespace(
            is_async=False,
            context_kwarg=None,
            annotations=types.SimpleNamespace(readOnlyHint=False),
        )
        operator._configure_http_runtime()
        child_pid = None
        try:
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
            self.assertTrue(marker.exists())
            child_pid = int(marker.read_text(encoding="ascii"))
            size_after_return = heartbeat.stat().st_size
            time.sleep(0.15)
            self.assertEqual(size_after_return, heartbeat.stat().st_size)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())
            self.assertEqual(
                0, operator._deployment_admission_snapshot()["drain_blocking_tool_calls"]
            )
        finally:
            if child_pid is not None:
                try:
                    operator.os.kill(child_pid, operator.signal.SIGKILL)
                except ProcessLookupError:
                    pass
            marker.unlink(missing_ok=True)
            heartbeat.unlink(missing_ok=True)

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

    def test_gate_allows_only_minimal_status_as_drain_neutral_readiness(self) -> None:
        operator = _load_operator_module()
        marker = {"state": "active", "active": True, "valid": True}
        calls: list[tuple[str, object]] = []

        async def original(name, arguments, *args, **kwargs):
            calls.append((name, arguments))
            return {"called": True}

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda name: types.SimpleNamespace(
            is_async=True,
            context_kwarg=None,
            annotations=types.SimpleNamespace(
                readOnlyHint=(name == "grabowski_status")
            ),
        )
        with patch.object(
            operator, "_read_deployment_admission_marker", return_value=marker
        ):
            operator._configure_http_runtime()
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "grabowski_status", {"view": "minimal"}
                )
            )
            self.assertTrue(result["called"])
            with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "grabowski_status", {"view": "evidence"}
                    )
                )
            with self.assertRaisesRegex(RuntimeError, "rejects new tool calls"):
                asyncio.run(operator.mcp._tool_manager.call_tool("write", {}))
        self.assertEqual(
            [("grabowski_status", {"view": "minimal"})], calls
        )
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_drain_neutral_readiness_uses_reserved_capacity_at_blocking_limit(
        self,
    ) -> None:
        operator = _load_operator_module()
        marker = {"state": "active", "active": True, "valid": True}
        calls: list[tuple[str, object]] = []

        async def original(name, arguments, *args, **kwargs):
            snapshot = operator._deployment_admission_snapshot()
            self.assertEqual(2, snapshot["active_tool_calls"])
            self.assertEqual(1, snapshot["drain_blocking_tool_calls"])
            self.assertEqual(1, snapshot["read_only_active_tool_calls"])
            calls.append((name, arguments))
            return {"called": True}

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda name: types.SimpleNamespace(
            is_async=True,
            context_kwarg=None,
            annotations=types.SimpleNamespace(
                readOnlyHint=(name == "grabowski_status")
            ),
        )
        with patch.object(
            operator, "_DEPLOYMENT_ADMISSION_ACTIVE_TOOL_CALL_REGISTRY_MAX", 1
        ), patch.object(
            operator, "_DEPLOYMENT_ADMISSION_DRAIN_NEUTRAL_RESERVE", 1
        ), patch.object(
            operator, "_read_deployment_admission_marker", return_value=marker
        ):
            blocker = operator._deployment_admission_register_tool_call(
                "queued-read", operator._DEPLOYMENT_ADMISSION_EXECUTION_KIND_SYNC
            )
            try:
                operator._configure_http_runtime()
                result = asyncio.run(
                    operator.mcp._tool_manager.call_tool(
                        "grabowski_status", {"view": "minimal"}
                    )
                )
                self.assertTrue(result["called"])
                self.assertEqual(
                    [("grabowski_status", {"view": "minimal"})], calls
                )
                self.assertEqual(
                    1, operator._deployment_admission_active_tool_calls()
                )
            finally:
                operator._deployment_admission_release_tool_call(blocker)

        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_sync_readiness_bypass_is_drain_neutral_and_schedules_trim_after_release(
        self,
    ) -> None:
        operator = _load_operator_module()
        marker = {"state": "active", "active": True, "valid": True}
        scheduled: list[tuple[float, int]] = []

        async def original(name, arguments, *args, **kwargs):
            self.assertEqual("grabowski_status", name)
            self.assertEqual({"view": "minimal"}, arguments)
            snapshot = operator._deployment_admission_snapshot()
            self.assertEqual(1, snapshot["active_tool_calls"])
            self.assertFalse(snapshot["active_tool_calls_sample"][0]["drain_blocking"])
            return {"called": True}

        def observe_schedule(delay_seconds: float) -> bool:
            scheduled.append(
                (
                    delay_seconds,
                    operator._deployment_admission_active_tool_calls(),
                )
            )
            return True

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator, "_read_deployment_admission_marker", return_value=marker
        ), patch.object(
            operator,
            "_schedule_sync_tool_allocator_trim_retry",
            side_effect=observe_schedule,
        ):
            operator._configure_http_runtime()
            result = asyncio.run(
                operator.mcp._tool_manager.call_tool(
                    "grabowski_status", {"view": "minimal"}
                )
            )

        self.assertTrue(result["called"])
        self.assertEqual([(0.0, 0)], scheduled)
        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_drain_neutral_sync_already_done_callback_never_trims_inline(
        self,
    ) -> None:
        operator = _load_operator_module()
        worker_future = operator.concurrent.futures.Future()
        worker_future.set_result({"called": True})
        timers: list[object] = []
        trim_threads: list[str] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        with patch.object(
            operator, "_submit_sync_tool_call", return_value=worker_future
        ), patch.object(
            operator.threading, "Timer", FakeTimer
        ), patch.object(
            operator,
            "_maybe_trim_sync_tool_allocator",
            side_effect=lambda: trim_threads.append(threading.current_thread().name)
            or False,
        ):
            started = time.perf_counter()
            result = asyncio.run(
                operator._run_drain_neutral_tool_call(
                    lambda: {"unused": True},
                    (),
                    {},
                    tool_name="already-done-probe",
                    tool=_sync_tool(),
                )
            )
            elapsed = time.perf_counter() - started

            self.assertTrue(result["called"])
            self.assertLess(elapsed, 0.1)
            self.assertEqual([], trim_threads)
            self.assertEqual(1, len(timers))
            self.assertEqual(0.0, timers[0].interval)
            self.assertTrue(timers[0].daemon)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

            timers[0].fire()

        self.assertEqual(1, len(trim_threads))
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

    def test_drain_neutral_sync_already_cancelled_callback_never_trims_inline(
        self,
    ) -> None:
        operator = _load_operator_module()
        worker_future = operator.concurrent.futures.Future()
        worker_future.cancel()
        timers: list[object] = []
        trim_threads: list[str] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        with patch.object(
            operator, "_submit_sync_tool_call", return_value=worker_future
        ), patch.object(
            operator.threading, "Timer", FakeTimer
        ), patch.object(
            operator,
            "_maybe_trim_sync_tool_allocator",
            side_effect=lambda: trim_threads.append(threading.current_thread().name)
            or False,
        ):
            started = time.perf_counter()
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(
                    operator._run_drain_neutral_tool_call(
                        lambda: {"unused": True},
                        (),
                        {},
                        tool_name="already-cancelled-probe",
                        tool=_sync_tool(),
                    )
                )
            elapsed = time.perf_counter() - started

            self.assertLess(elapsed, 0.1)
            self.assertEqual([], trim_threads)
            self.assertEqual(1, len(timers))
            self.assertEqual(0.0, timers[0].interval)
            self.assertTrue(timers[0].daemon)
            self.assertEqual(0, operator._deployment_admission_active_tool_calls())

            timers[0].fire()

        self.assertEqual(1, len(trim_threads))
        self.assertIsNone(operator._SYNC_TOOL_ALLOCATOR_TRIM_RETRY_TIMER)

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

    def test_gate_sync_marker_bound_job_observer_bypasses_shared_backlog(self) -> None:
        operator = _load_operator_module()
        shared_started = threading.Event()
        shared_release = threading.Event()
        observer_ran = threading.Event()
        shared_executor = ThreadPoolExecutor(max_workers=1)
        drain_neutral_executor = ThreadPoolExecutor(max_workers=1)
        marker_active = [False]

        async def call_tool(name, _arguments, *args, **kwargs):
            if name == "regular-read":
                shared_started.set()
                if not shared_release.wait(timeout=5):
                    raise RuntimeError("shared release timed out")
            elif name == operator.deployment_observer.OPERATION:
                observer_ran.set()
            return {"called": True}

        def marker():
            if marker_active[0]:
                return {"state": "active", "active": True, "valid": True}
            return {"state": "absent", "active": False, "valid": False}

        def observer_evidence(name, *_args, **_kwargs):
            if name == operator.deployment_observer.OPERATION and marker_active[0]:
                return {"marker_bound": True}
            return None

        self.assertEqual(
            "grabowski_job_status", operator.deployment_observer.OPERATION
        )
        operator.mcp._tool_manager.call_tool = call_tool
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        operator._SYNC_TOOL_EXECUTOR = shared_executor
        operator._SYNC_TOOL_DRAIN_NEUTRAL_OBSERVER_EXECUTOR = drain_neutral_executor
        with patch.object(
            operator, "_read_deployment_admission_marker", side_effect=marker
        ), patch.object(
            operator,
            "_deployment_observer_request_evidence",
            side_effect=observer_evidence,
        ), patch.object(
            operator, "_schedule_sync_tool_allocator_trim_retry", return_value=True
        ):
            operator._configure_http_runtime()

            async def exercise() -> None:
                ordinary = asyncio.create_task(
                    operator.mcp._tool_manager.call_tool("regular-read", {})
                )
                self.assertTrue(
                    await asyncio.to_thread(shared_started.wait, 2)
                )

                marker_active[0] = True
                observer = await asyncio.wait_for(
                    operator.mcp._tool_manager.call_tool(
                        operator.deployment_observer.OPERATION, {}
                    ),
                    timeout=1,
                )
                self.assertTrue(observer["called"])
                self.assertTrue(observer_ran.is_set())
                self.assertFalse(shared_release.is_set())

                marker_active[0] = False
                shared_release.set()
                self.assertTrue((await ordinary)["called"])

            try:
                asyncio.run(exercise())
            finally:
                marker_active[0] = False
                shared_release.set()
                shared_executor.shutdown(wait=True, cancel_futures=True)
                drain_neutral_executor.shutdown(
                    wait=True, cancel_futures=True
                )

        self.assertEqual(0, operator._deployment_admission_active_tool_calls())

    def test_gate_overlapping_sync_bypasses_do_not_trim_until_global_idle(self) -> None:
        operator = _load_operator_module()
        marker = {
            "kind": "grabowski_deployment_admission_observation",
            "state": "active",
            "active": True,
            "valid": True,
        }
        observer_started = threading.Event()
        readiness_started = threading.Event()
        release_observer = threading.Event()
        release_readiness = threading.Event()
        observed_active_calls: list[int] = []
        timers: list[object] = []

        class FakeTimer:
            def __init__(self, interval, function, args=()):
                self.interval = interval
                self.function = function
                self.args = args
                self.daemon = False
                timers.append(self)

            def start(self):
                pass

            def cancel(self):
                pass

            def fire(self):
                self.function(*self.args)

        async def original(name, arguments, *args, **kwargs):
            if name == operator.deployment_observer.OPERATION:
                observer_started.set()
                if not release_observer.wait(timeout=5):
                    raise RuntimeError("observer release timed out")
            else:
                self.assertEqual("grabowski_status", name)
                self.assertEqual({"view": "minimal"}, arguments)
                readiness_started.set()
                if not release_readiness.wait(timeout=5):
                    raise RuntimeError("readiness release timed out")
            return {"called": True}

        def observer_evidence(name, *_args, **_kwargs):
            if name == operator.deployment_observer.OPERATION:
                return {"marker_bound": True}
            return None

        def observe_trim() -> bool:
            observed_active_calls.append(
                operator._deployment_admission_active_tool_calls()
            )
            return False

        operator.mcp._tool_manager.call_tool = original
        operator.mcp._tool_manager.get_tool = lambda _name: _sync_tool()
        with patch.object(
            operator, "_read_deployment_admission_marker", return_value=marker
        ), patch.object(
            operator,
            "_deployment_observer_request_evidence",
            side_effect=observer_evidence,
        ), patch.object(
            operator.threading,
            "Timer",
            FakeTimer,
        ), patch.object(
            operator,
            "_maybe_trim_sync_tool_allocator",
            side_effect=observe_trim,
        ):
            operator._configure_http_runtime()

            async def exercise() -> None:
                observer = asyncio.create_task(
                    operator.mcp._tool_manager.call_tool(
                        operator.deployment_observer.OPERATION, {}
                    )
                )
                readiness = asyncio.create_task(
                    operator.mcp._tool_manager.call_tool(
                        "grabowski_status", {"view": "minimal"}
                    )
                )
                self.assertTrue(await asyncio.to_thread(observer_started.wait, 2))
                self.assertTrue(await asyncio.to_thread(readiness_started.wait, 2))
                snapshot = operator._deployment_admission_snapshot()
                self.assertEqual(2, snapshot["active_tool_calls"])
                self.assertTrue(
                    all(
                        item["drain_blocking"] is False
                        for item in snapshot["active_tool_calls_sample"]
                    )
                )
                release_observer.set()
                await observer
                self.assertEqual(1, operator._deployment_admission_active_tool_calls())
                self.assertEqual(1, len(timers))
                timers[0].fire()
                self.assertEqual([1], observed_active_calls)

                release_readiness.set()
                await readiness
                self.assertEqual(2, len(timers))
                timers[1].fire()

            try:
                asyncio.run(exercise())
            finally:
                release_observer.set()
                release_readiness.set()

        self.assertEqual([1, 0], observed_active_calls)
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

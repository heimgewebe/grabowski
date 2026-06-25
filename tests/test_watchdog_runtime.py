from __future__ import annotations

from pathlib import Path
import importlib.util
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "watchdog_runtime.py"


def load_module():
    spec = importlib.util.spec_from_file_location("watchdog_runtime", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("watchdog_runtime.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["watchdog_runtime"] = module
    spec.loader.exec_module(module)
    return module


watchdog = load_module()


class WatchdogRuntimeTests(unittest.TestCase):
    def _probe(self, *, operators: list[int], age: float = 120.0):
        with (
            patch.object(
                watchdog,
                "service_properties",
                return_value={
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "101",
                },
            ),
            patch.object(watchdog, "main_identity_ok", return_value=True),
            patch.object(watchdog, "process_age_seconds", return_value=age),
            patch.object(watchdog, "operator_candidates", return_value=operators),
            patch.object(watchdog, "http_probe", return_value=True),
        ):
            return watchdog.probe_runtime(
                service="tunnel-client-grabowski.service",
                profile="grabowski",
                expected_module="grabowski_operator",
                runtime_root=Path("/runtime"),
                health_url="http://127.0.0.1:18080/healthz",
                ready_url="http://127.0.0.1:18080/readyz",
                startup_grace=20,
                http_timeout=1,
            )

    def test_green_http_without_operator_is_unhealthy(self) -> None:
        result = self._probe(operators=[])

        self.assertEqual(result.status, "unhealthy")
        self.assertEqual(result.reasons, ("operator-count-0",))
        self.assertIsNone(result.operator_pid)

    def test_exactly_one_operator_and_green_http_is_healthy(self) -> None:
        result = self._probe(operators=[202])

        self.assertEqual(result.status, "healthy")
        self.assertEqual(result.main_pid, 101)
        self.assertEqual(result.operator_pid, 202)

    def test_startup_grace_suppresses_early_restart(self) -> None:
        result = self._probe(operators=[], age=4.0)

        self.assertEqual(result.status, "startup_grace")
        self.assertEqual(result.reasons, ("operator-count-0",))

    def test_failure_threshold_requires_three_consecutive_failures(self) -> None:
        state = watchdog.WatchdogState()
        first = watchdog.decide_failure(
            state,
            now=100,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )
        second = watchdog.decide_failure(
            first.state,
            now=130,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )
        third = watchdog.decide_failure(
            second.state,
            now=160,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )

        self.assertEqual(first.action, "observe")
        self.assertEqual(second.action, "observe")
        self.assertEqual(third.action, "restart")
        self.assertEqual(third.state.consecutive_failures, 0)
        self.assertEqual(third.state.restart_timestamps, [160])

    def test_restart_budget_blocks_fourth_restart_in_window(self) -> None:
        state = watchdog.WatchdogState(
            consecutive_failures=2,
            restart_timestamps=[100, 200, 300],
        )
        decision = watchdog.decide_failure(
            state,
            now=400,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )

        self.assertEqual(decision.action, "budget-exhausted")
        self.assertEqual(decision.state.restart_timestamps, [100, 200, 300])

    def test_restart_budget_prunes_old_entries(self) -> None:
        state = watchdog.WatchdogState(
            consecutive_failures=2,
            restart_timestamps=[1, 200, 300],
        )
        decision = watchdog.decide_failure(
            state,
            now=1000,
            failure_threshold=3,
            max_restarts=3,
            restart_window=900,
        )

        self.assertEqual(decision.action, "restart")
        self.assertEqual(decision.state.restart_timestamps, [200, 300, 1000])

    def test_main_identity_requires_exact_profile_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            pid_dir = proc / "42"
            pid_dir.mkdir()
            (pid_dir / "cmdline").write_bytes(
                b"/home/alex/.local/bin/tunnel-client\0run\0--profile\0grabowski\0"
            )
            self.assertTrue(watchdog.main_identity_ok(proc, 42, "grabowski"))

            (pid_dir / "cmdline").write_bytes(
                b"/home/alex/.local/bin/tunnel-client\0run\0--profile\0grabowski-old\0"
            )
            self.assertFalse(watchdog.main_identity_ok(proc, 42, "grabowski"))

    def test_state_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            state = root / "watchdog-state.json"
            state.symlink_to(target)

            with self.assertRaisesRegex(watchdog.WatchdogError, "state-file-is-symlink"):
                watchdog.load_state(state)

    def test_operator_identity_requires_stable_runtime_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = root / "proc"
            runtime = root / "runtime"
            python = runtime / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("", encoding="utf-8")

            (proc / "1").mkdir(parents=True)
            (proc / "1/status").write_text("PPid:\t0\n", encoding="utf-8")
            (proc / "2").mkdir()
            (proc / "2/status").write_text("PPid:\t1\n", encoding="utf-8")
            (proc / "2/cmdline").write_bytes(
                f"{python}\0-m\0grabowski_operator\0".encode()
            )
            (proc / "2/exe").symlink_to(python)

            self.assertEqual(
                watchdog.operator_candidates(proc, 1, runtime, "grabowski_operator"),
                [2],
            )

            (proc / "2/cmdline").write_bytes(
                f"{python}\0-m\0other_module\0".encode()
            )
            self.assertEqual(
                watchdog.operator_candidates(proc, 1, runtime, "grabowski_operator"),
                [],
            )


if __name__ == "__main__":
    unittest.main()
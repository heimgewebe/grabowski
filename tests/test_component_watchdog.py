from pathlib import Path
import importlib.util
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools" / "component_watchdog.py"

spec = importlib.util.spec_from_file_location("component_watchdog_test", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("component watchdog could not be loaded")
watchdog = importlib.util.module_from_spec(spec)
sys.modules["component_watchdog_test"] = watchdog
spec.loader.exec_module(watchdog)


class ComponentWatchdogTests(unittest.TestCase):
    def test_non_loopback_urls_are_rejected(self) -> None:
        with self.assertRaisesRegex(watchdog.WatchdogError, "non-loopback"):
            watchdog.loopback_http_url("http://0.0.0.0:18181/mcp")
        with self.assertRaisesRegex(watchdog.WatchdogError, "non-loopback"):
            watchdog.loopback_http_url("https://127.0.0.1:18181/mcp")

    def test_restart_threshold_and_budget(self) -> None:
        state = watchdog.WatchdogState()
        action, state = watchdog.decide(state, now=100, failure_threshold=2, max_restarts=1, restart_window=900)
        self.assertEqual("observe", action)
        action, state = watchdog.decide(state, now=101, failure_threshold=2, max_restarts=1, restart_window=900)
        self.assertEqual("restart", action)
        state.consecutive_failures = 1
        action, _ = watchdog.decide(state, now=102, failure_threshold=2, max_restarts=1, restart_window=900)
        self.assertEqual("budget-exhausted", action)

    def test_services_are_independent(self) -> None:
        operator = watchdog.normalize_args(watchdog.parser().parse_args(["--component", "operator"]))
        tunnel = watchdog.normalize_args(watchdog.parser().parse_args(["--component", "tunnel"]))
        self.assertEqual("grabowski-operator.service", operator.service)
        self.assertEqual("tunnel-client-grabowski.service", tunnel.service)


if __name__ == "__main__":
    unittest.main()

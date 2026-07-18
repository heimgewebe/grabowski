from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "systemd"


class WatchdogSystemdContractTests(unittest.TestCase):
    def test_tunnel_service_has_bounded_start_limit(self) -> None:
        unit = (SYSTEMD / "tunnel-client-grabowski.service.example").read_text(
            encoding="utf-8"
        )
        drop_in = (
            SYSTEMD
            / "tunnel-client-grabowski.service.d"
            / "80-restart-budget.conf.example"
        ).read_text(encoding="utf-8")

        self.assertIn("Restart=on-failure", unit)
        self.assertIn("StartLimitIntervalSec=5min", unit)
        self.assertIn("StartLimitBurst=5", unit)
        self.assertNotIn("WatchdogSec=", unit)
        self.assertIn("StartLimitIntervalSec=5min", drop_in)
        self.assertIn("StartLimitBurst=5", drop_in)

    def test_tunnel_unit_has_single_flat_restart_truth(self) -> None:
        unit = (SYSTEMD / "tunnel-client-grabowski.service.example").read_text(
            encoding="utf-8"
        )
        drop_in = (
            SYSTEMD
            / "tunnel-client-grabowski.service.d"
            / "80-restart-budget.conf.example"
        ).read_text(encoding="utf-8")

        def directives(text: str) -> dict[str, str]:
            result: dict[str, str] = {}
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "[")) and "=" in line:
                    key, value = line.split("=", 1)
                    result[key] = value
            return result

        unit_directives = directives(unit)
        drop_in_directives = directives(drop_in)
        # Restart=on-failure stays the fast main-process fallback with a flat
        # RestartSec; escalating backoff belongs to the semantic watchdog only
        # (systemd 249 has no RestartSteps), so no competing truth here.
        self.assertEqual("5", unit_directives.get("RestartSec"))
        self.assertNotIn("RestartSteps", unit_directives)
        self.assertNotIn("RestartMaxDelaySec", unit_directives)
        for key in ("StartLimitIntervalSec", "StartLimitBurst"):
            self.assertEqual(unit_directives[key], drop_in_directives[key])

    def test_semantic_watchdog_runs_every_thirty_seconds(self) -> None:
        timer = (SYSTEMD / "grabowski-watchdog.timer.example").read_text(
            encoding="utf-8"
        )
        self.assertIn("OnUnitActiveSec=30s", timer)
        self.assertIn("AccuracySec=1s", timer)
        self.assertIn("Unit=grabowski-watchdog.service", timer)

    def test_watchdog_service_uses_stable_installed_script(self) -> None:
        unit = (SYSTEMD / "grabowski-watchdog.service.example").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "%h/.local/libexec/grabowski/watchdog_runtime.py",
            unit,
        )
        self.assertIn("GRABOWSKI_WATCHDOG_EXPECTED_MODULE", unit)
        self.assertIn("ReadWritePaths=%h/.local/state/grabowski", unit)
        self.assertIn("NoNewPrivileges=yes", unit)


if __name__ == "__main__":
    unittest.main()
from __future__ import annotations

import configparser
from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "systemd"


class WatchdogTimerContractTests(unittest.TestCase):
    CASES = {
        "grabowski-operator-watchdog.timer.example": {
            "calendar": "*-*-* *:*:00",
            "unit": "grabowski-operator-watchdog.service",
        },
        "grabowski-tunnel-watchdog.timer.example": {
            "calendar": "*-*-* *:*:00,30",
            "unit": "grabowski-tunnel-watchdog.service",
        },
    }

    @staticmethod
    def load(path: Path) -> configparser.ConfigParser:
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        with path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
        return parser

    def test_watchdog_timers_keep_a_future_calendar_elapse_armed(self) -> None:
        for filename, expected in self.CASES.items():
            with self.subTest(filename=filename):
                path = SYSTEMD / filename
                text = path.read_text(encoding="utf-8")
                timer = self.load(path)["Timer"]

                self.assertNotIn("OnUnitActiveSec", timer)
                self.assertEqual("45s", timer["OnBootSec"])
                self.assertEqual(expected["calendar"], timer["OnCalendar"])
                self.assertEqual("5s", timer["AccuracySec"])
                self.assertEqual("3s", timer["RandomizedDelaySec"])
                self.assertEqual("true", timer["Persistent"].lower())
                self.assertEqual(expected["unit"], timer["Unit"])
                self.assertIn(
                    "Calendar scheduling is independent of the oneshot service activation state.",
                    text,
                )

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze unavailable")
    def test_calendar_expressions_are_accepted_by_systemd(self) -> None:
        for filename, expected in self.CASES.items():
            with self.subTest(filename=filename):
                completed = subprocess.run(
                    ["systemd-analyze", "calendar", expected["calendar"]],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(
                    0,
                    completed.returncode,
                    msg=(completed.stdout + completed.stderr),
                )


if __name__ == "__main__":
    unittest.main()

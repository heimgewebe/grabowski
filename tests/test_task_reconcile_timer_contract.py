from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TIMER = ROOT / "systemd" / "grabowski-reconcile-tasks.timer.example"
SERVICE = ROOT / "systemd" / "grabowski-reconcile-tasks.service.example"


class TaskReconcileTimerContractTests(unittest.TestCase):
    def test_reconcile_timer_preserves_completion_cadence_with_calendar_fallback(self) -> None:
        source = TIMER.read_text(encoding="utf-8")
        directives = {
            line.strip()
            for line in source.splitlines()
            if line.strip() and not line.lstrip().startswith(("#", "["))
        }

        self.assertIn("OnUnitInactiveSec=1min", directives)
        self.assertIn("OnCalendar=*-*-* *:0/5:00", directives)
        self.assertIn("Persistent=true", directives)
        self.assertIn("Unit=grabowski-reconcile-tasks.service", directives)
        self.assertFalse(any(line.startswith("OnUnitActiveSec=") for line in directives))

    def test_reconcile_target_remains_bounded_oneshot(self) -> None:
        source = SERVICE.read_text(encoding="utf-8")

        self.assertIn("Type=oneshot", source)
        self.assertIn("--mode refresh --batch-size 100", source)
        self.assertIn("TimeoutStartSec=120s", source)


if __name__ == "__main__":
    unittest.main()

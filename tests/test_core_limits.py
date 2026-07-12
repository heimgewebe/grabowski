from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CoreLimitContractTests(unittest.TestCase):
    def test_operator_service_disables_core_dumps_once_without_changing_other_hardening(self) -> None:
        service = (
            ROOT / "systemd" / "grabowski-operator.service.example"
        ).read_text(encoding="utf-8")
        self.assertEqual(service.splitlines().count("LimitCORE=0"), 1)
        for directive in (
            "NoNewPrivileges=yes",
            "PrivateTmp=yes",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
        ):
            self.assertIn(directive, service)

    def test_job_task_and_worker_launchers_disable_core_dumps_exactly_once(self) -> None:
        sources = {
            "job": ROOT / "src" / "grabowski_operator.py",
            "task": ROOT / "src" / "grabowski_tasks.py",
            "worker": ROOT / "src" / "grabowski_workers.py",
        }
        for label, path in sources.items():
            with self.subTest(label=label):
                source = path.read_text(encoding="utf-8")
                self.assertEqual(source.count('"--property=LimitCORE=0"'), 1)


if __name__ == "__main__":
    unittest.main()

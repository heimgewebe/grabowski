from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

SPEC = importlib.util.spec_from_file_location(
    "run_scheduled_deploy_cold_reentry_test",
    TOOLS / "run_scheduled_deploy.py",
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class ColdReentryObserverIsolationTests(unittest.TestCase):
    observer_environment = {
        "GRABOWSKI_JOB_UNIT": "grabowski-job-0123456789ab",
        "GRABOWSKI_JOB_DIRECTORY": "/tmp/grabowski-job-0123456789ab",
        "GRABOWSKI_JOB_METADATA_PATH": "/tmp/grabowski-job-0123456789ab/metadata.json",
    }
    decision = {
        "execution_head": "e" * 40,
        "resume_target_head": "f" * 40,
        "resume_binding_sha256": "b" * 64,
    }

    @staticmethod
    def completed_result() -> dict[str, object]:
        return {
            "receipt": {
                "receipt_sha256": "c" * 64,
                "resume_phase": "S3_retire_green",
                "resumed_cutover_id": "bgc-test",
            },
            "receipt_path": "/tmp/bgcr-test.json",
            "receipt_persisted": True,
            "outcome": "completed",
        }

    def test_resume_hides_only_scheduler_observer_discovery_and_restores_it(self) -> None:
        observed: dict[str, str | None] = {}

        def fake_resume(**_kwargs: object) -> dict[str, object]:
            observed.update(
                {
                    name: os.environ.get(name)
                    for name in self.observer_environment
                }
            )
            self.assertEqual(os.environ.get("T084_UNRELATED_SENTINEL"), "preserved")
            return self.completed_result()

        environment = {
            **self.observer_environment,
            "T084_UNRELATED_SENTINEL": "preserved",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            with (
                mock.patch.object(
                    runner.deploy_dual,
                    "resume_production_blue_green_cutover",
                    side_effect=fake_resume,
                ),
                mock.patch.object(runner, "emit"),
            ):
                result = runner.run_midcutover_resume(
                    repo=ROOT,
                    decision=self.decision,
                )

            self.assertEqual(
                observed,
                {name: None for name in self.observer_environment},
            )
            for name, value in self.observer_environment.items():
                self.assertEqual(os.environ.get(name), value)
            self.assertEqual(os.environ.get("T084_UNRELATED_SENTINEL"), "preserved")
            self.assertEqual(result["outcome"], "completed")

    def test_resume_restores_scheduler_observer_discovery_after_failure(self) -> None:
        with mock.patch.dict(os.environ, self.observer_environment, clear=False):
            with mock.patch.object(
                runner.deploy_dual,
                "resume_production_blue_green_cutover",
                side_effect=RuntimeError("resume failed"),
            ):
                with self.assertRaisesRegex(RuntimeError, "resume failed"):
                    runner.run_midcutover_resume(
                        repo=ROOT,
                        decision=self.decision,
                    )

            for name, value in self.observer_environment.items():
                self.assertEqual(os.environ.get(name), value)


if __name__ == "__main__":
    unittest.main()

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
    SOURCE_A = "a" * 64
    SOURCE_B = "d" * 64
    observer_environment = {
        "GRABOWSKI_JOB_UNIT": "grabowski-job-0123456789ab",
        "GRABOWSKI_JOB_DIRECTORY": "/tmp/grabowski-job-0123456789ab",
        "GRABOWSKI_JOB_METADATA_PATH": "/tmp/grabowski-job-0123456789ab/metadata.json",
    }

    @classmethod
    def decision(
        cls,
        *,
        execution_head: str = "e" * 40,
        resume_target_head: str = "f" * 40,
        execution_source_identity: str | None = None,
        resume_source_identity: str | None = None,
    ) -> dict[str, object]:
        execution_source_identity = execution_source_identity or cls.SOURCE_A
        resume_source_identity = resume_source_identity or cls.SOURCE_A
        return {
            "execution_head": execution_head,
            "resume_target_head": resume_target_head,
            "resume_binding_sha256": "b" * 64,
            "execution_source_identity_sha256": execution_source_identity,
            "classification": {
                "resume_binding": {
                    "source_identity_sha256": resume_source_identity,
                }
            },
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

    def _capture_resume_environment(
        self, decision: dict[str, object]
    ) -> tuple[dict[str, str | None], dict[str, object]]:
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
                result = runner.run_midcutover_resume(repo=ROOT, decision=decision)

            for name, value in self.observer_environment.items():
                self.assertEqual(os.environ.get(name), value)
            self.assertEqual(os.environ.get("T084_UNRELATED_SENTINEL"), "preserved")
        return observed, result

    def test_historical_head_resume_hides_scheduler_observer_and_restores_it(self) -> None:
        observed, result = self._capture_resume_environment(self.decision())
        self.assertEqual(
            observed,
            {name: None for name in self.observer_environment},
        )
        self.assertEqual(result["outcome"], "completed")

    def test_matching_head_and_source_preserve_scheduler_observer(self) -> None:
        head = "f" * 40
        observed, result = self._capture_resume_environment(
            self.decision(execution_head=head, resume_target_head=head)
        )
        self.assertEqual(observed, self.observer_environment)
        self.assertEqual(result["outcome"], "completed")

    def test_matching_head_with_source_mismatch_hides_scheduler_observer(self) -> None:
        head = "f" * 40
        observed, _result = self._capture_resume_environment(
            self.decision(
                execution_head=head,
                resume_target_head=head,
                execution_source_identity=self.SOURCE_B,
                resume_source_identity=self.SOURCE_A,
            )
        )
        self.assertEqual(
            observed,
            {name: None for name in self.observer_environment},
        )

    def test_missing_authenticated_resume_source_hides_scheduler_observer(self) -> None:
        head = "f" * 40
        decision = self.decision(execution_head=head, resume_target_head=head)
        classification = decision["classification"]
        assert isinstance(classification, dict)
        binding = classification["resume_binding"]
        assert isinstance(binding, dict)
        binding.pop("source_identity_sha256")
        observed, _result = self._capture_resume_environment(decision)
        self.assertEqual(
            observed,
            {name: None for name in self.observer_environment},
        )

    def test_isolated_resume_restores_scheduler_observer_after_failure(self) -> None:
        with mock.patch.dict(os.environ, self.observer_environment, clear=False):
            with mock.patch.object(
                runner.deploy_dual,
                "resume_production_blue_green_cutover",
                side_effect=RuntimeError("resume failed"),
            ):
                with self.assertRaisesRegex(RuntimeError, "resume failed"):
                    runner.run_midcutover_resume(repo=ROOT, decision=self.decision())

            for name, value in self.observer_environment.items():
                self.assertEqual(os.environ.get(name), value)


if __name__ == "__main__":
    unittest.main()

"""PR #1662: a verified never-started resume must not poison the deploy index.

Model the genuine _start_job persisted failure: systemd-run failed, an
authoritative systemctl query said the reserved unit never started, and the
generic runner-finalization file cannot exist. The next recovery must be able
to retire just this reservation without waiving ambiguous or started effects.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_self_deploy import SELF_DEPLOY as DEPLOY


class NeverStartedResumeReservationTests(unittest.TestCase):
    UNIT = "grabowski-job-456789abcdef"
    REPOSITORY = Path("/home/alex/repos/grabowski")
    HEAD = "a" * 40
    CUTOVER = "cutover-pr1662-nonstart"
    BINDING = "b" * 64

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "jobs"
        self.root.mkdir(mode=0o700)
        self.entry = self.root / self.UNIT
        self.entry.mkdir(mode=0o700)
        self.command = DEPLOY._midcutover_resume_command(
            self.REPOSITORY,
            self.REPOSITORY / DEPLOY.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH,
            self.HEAD,
            self.CUTOVER,
            self.BINDING,
        )
        self.dispatch = {
            "query_valid": True,
            "outcome": "not_started",
            "load_state": "not-found",
            "active_state": "inactive",
        }
        self.terminal = {
            "source": "systemd-run-launch",
            "query_valid": True,
            "final_status": "launch_failed",
            "systemd_visible": False,
        }
        self.meta = {
            "unit": self.UNIT,
            "job_id": self.UNIT.removeprefix("grabowski-job-"),
            "argv": self.command,
            "argv_sha256": DEPLOY._deploy_command_sha256(self.command),
            "cwd": str(self.REPOSITORY),
            "final_status": "launch_failed",
            "dispatch_outcome": "not_started",
            "dispatch_readback": self.dispatch,
            "terminalization_evidence": self.terminal,
            "launcher_evidence": {
                "source": "systemd-run",
                "returncode": 1,
                "stdout_sha256": "0" * 64,
                "stderr_sha256": "1" * 64,
                "stdout_bytes": 0,
                "stderr_bytes": 0,
            },
            "finalization_contract": {
                "kind": "grabowski_job_finalization",
                "unit": self.UNIT,
                "job_id": self.UNIT.removeprefix("grabowski-job-"),
                "argv_sha256": DEPLOY._deploy_command_sha256(self.command),
            },
        }
        self.status = {
            "unit": self.UNIT,
            "metadata": self.meta,
            "final_status": "launch_failed",
            "systemd_visible": False,
            "finalization_receipt": {
                "configured": True,
                "valid": False,
                "state": "missing_receipt",
            },
            "terminalization_evidence": {
                **self.terminal,
                "query_valid": False,
            },
        }

    def _classify(self, *, metadata=None, status=None, live=None) -> bool:
        meta = self.meta if metadata is None else metadata
        state = self.status if status is None else status
        reply = self.dispatch if live is None else live
        with (
            mock.patch.object(DEPLOY.operator, "_read_job_metadata", return_value=meta),
            mock.patch.object(DEPLOY.operator, "grabowski_job_status", return_value=state),
            mock.patch.object(DEPLOY.operator, "_unit_dispatch_readback", return_value=reply),
        ):
            return DEPLOY._classify_indexed_job(self.entry)["terminal"]

    def test_launch_failed_after_verified_nonstart_can_retire_promoted_reservation(self) -> None:
        # The recovery dispatcher created a directory, then the exception
        # handler promoted pending_unit into units before clearing pending.
        DEPLOY._write_deploy_index(
            self.root, units=[], pending_unit=self.UNIT
        )
        with (
            mock.patch.object(DEPLOY.operator, "_read_job_metadata", return_value=self.meta),
            mock.patch.object(DEPLOY.operator, "grabowski_job_status", return_value=self.status),
            mock.patch.object(DEPLOY.operator, "_unit_dispatch_readback", return_value=self.dispatch) as verify,
        ):
            promoted = DEPLOY._deploy_index(self.root)
            self.assertEqual(promoted["units"], [self.UNIT])
            self.assertIsNone(promoted["pending_unit"])
            self.assertTrue(DEPLOY._classify_indexed_job(self.entry)["terminal"])
            # Restart/bootstrap must also not resurrect a known non-start.
            bootstrapped = DEPLOY._bootstrap_deploy_index(self.root, read_only=True)
        self.assertEqual(bootstrapped["units"], [])
        self.assertGreaterEqual(verify.call_count, 2)

    def test_deny_missing_or_contradictory_dispatch_or_terminalization(self) -> None:
        self.assertTrue(self._classify())
        for target, key, invalid in (
            ("meta", "dispatch_outcome", "outcome_unknown"),
            ("meta", "dispatch_readback", {"query_valid": False, "outcome": "not_started"}),
            ("meta", "dispatch_readback", {"query_valid": True, "outcome": "started"}),
            ("meta", "terminalization_evidence", {"final_status": "launch_failed"}),
            ("meta", "launcher_evidence", {"source": "systemd-run", "returncode": 0}),
            ("meta", "final_status", "failed"),
            ("status", "final_status", "failed"),
            ("status", "systemd_visible", True),
            ("status", "finalization_receipt", {"configured": True, "valid": False, "state": "invalid_receipt"}),
            ("status", "finalization_receipt", {"configured": True, "valid": True, "state": "valid"}),
            ("status", "unit", "grabowski-job-ffffffffffff"),
        ):
            with self.subTest(target=target, key=key, invalid=invalid):
                metadata = deepcopy(self.meta)
                status = deepcopy(self.status)
                if target == "meta":
                    metadata[key] = invalid
                    status["metadata"] = metadata
                else:
                    status[key] = invalid
                self.assertFalse(self._classify(metadata=metadata, status=status))
        for evidence in (
            {"query_valid": False, "outcome": "outcome_unknown"},
            {"query_valid": True, "outcome": "started", "load_state": "loaded", "active_state": "active"},
            {"query_valid": True, "outcome": "not_started", "load_state": "loaded", "active_state": "inactive"},
        ):
            with self.subTest(live=evidence):
                self.assertFalse(self._classify(live=evidence))

    def test_deny_command_hash_or_foreign_job_even_with_valid_dispatch_readback(self) -> None:
        metadata = deepcopy(self.meta)
        metadata["argv_sha256"] = "f" * 64
        status = deepcopy(self.status)
        status["metadata"] = metadata
        with self.assertRaises(DEPLOY.IndexedRuntimeJobConflict):
            self._classify(metadata=metadata, status=status)
        metadata = deepcopy(self.meta)
        metadata["cwd"] = "/tmp/foreign"
        status["metadata"] = metadata
        with self.assertRaises(DEPLOY.IndexedRuntimeJobConflict):
            self._classify(metadata=metadata, status=status)


if __name__ == "__main__":
    unittest.main()

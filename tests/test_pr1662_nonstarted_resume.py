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


    def test_scheduled_deploy_nonstart_bootstrap_and_reconciliation(self) -> None:
        """The same proven non-start must retire a scheduled deploy, not only a resume."""
        command = DEPLOY._deploy_command(
            self.REPOSITORY,
            self.REPOSITORY / DEPLOY.RUNNER_RELATIVE_PATH,
            self.HEAD, 8, source_identity_sha256="c" * 64,
        )
        metadata = deepcopy(self.meta)
        metadata["argv"] = command
        metadata["argv_sha256"] = DEPLOY._deploy_command_sha256(command)
        metadata["finalization_contract"]["argv_sha256"] = metadata["argv_sha256"]
        status = deepcopy(self.status)
        status["metadata"] = metadata
        self.assertTrue(self._classify(metadata=metadata, status=status))
        with (
            mock.patch.object(DEPLOY.operator, "_read_job_metadata", return_value=metadata),
            mock.patch.object(DEPLOY.operator, "grabowski_job_status", return_value=status),
            mock.patch.object(DEPLOY.operator, "_unit_dispatch_readback", return_value=self.dispatch),
        ):
            self.assertEqual(DEPLOY._bootstrap_deploy_index(self.root, read_only=True)["units"], [])
            with (
                mock.patch.object(DEPLOY.operator, "_jobs_root", return_value=self.root),
                mock.patch.object(
                    DEPLOY, "_deploy_index", return_value={"units": [self.UNIT], "pending_unit": None}
                ),
            ):
                self.assertIsNone(DEPLOY._matching_inflight_deploy_job(command, self.REPOSITORY))
        for wrong in (
            ("dispatch_outcome", "outcome_unknown"),
            ("launcher_evidence", {"source": "systemd-run", "returncode": 0}),
            ("final_status", "failed"),
        ):
            bad = deepcopy(metadata)
            bad[wrong[0]] = wrong[1]
            bad_status = deepcopy(status)
            bad_status["metadata"] = bad
            self.assertFalse(self._classify(metadata=bad, status=bad_status))
        for readback in (
            {"query_valid": False, "outcome": "not_started"},
            {"query_valid": True, "outcome": "started", "load_state": "loaded", "active_state": "active"},
        ):
            self.assertFalse(self._classify(metadata=metadata, status=status, live=readback))


class FailedPreCutoverDeployTerminalityTests(unittest.TestCase):
    """Authentic persisted pre-switch failure may retire; effects cannot."""

    UNIT = "grabowski-job-789abcdef012"
    REPOSITORY = Path("/home/alex/repos/grabowski")
    HEAD = "e" * 40
    SOURCE = "d" * 64

    def setUp(self) -> None:
        from test_runtime_deploy_schedule import dual
        self.dual = dual
        from test_self_deploy import RUNNER
        self.runner = RUNNER
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.jobs = Path(self.temp.name) / "jobs"
        self.cutovers = Path(self.temp.name) / "cutovers"
        self.jobs.mkdir(mode=0o700)
        self.cutovers.mkdir(mode=0o700)
        self.entry = self.jobs / self.UNIT
        self.entry.mkdir(mode=0o700)
        self.command = DEPLOY._deploy_command(
            self.REPOSITORY, self.REPOSITORY / DEPLOY.RUNNER_RELATIVE_PATH,
            self.HEAD, 8, source_identity_sha256=self.SOURCE,
        )
        self.paths = {
            key: str(self.entry / filename)
            for key, filename in (
                ("metadata", "metadata.json"), ("stdout", "stdout.log"),
                ("stderr", "stderr.log"), ("finalization", "finalization.json"),
            )
        }
        sha = DEPLOY._deploy_command_sha256(self.command)
        self.metadata = {
            "unit": self.UNIT,
            "job_id": self.UNIT.removeprefix("grabowski-job-"),
            "argv": self.command,
            "argv_sha256": sha,
            "cwd": str(self.REPOSITORY),
            "final_status": "launch_submitted",
            "finalization_contract": {
                "kind": "grabowski_runtime_deploy_finalization",
                "unit": self.UNIT,
                "job_id": self.UNIT.removeprefix("grabowski-job-"),
                "argv_sha256": sha,
                "expected_head": self.HEAD,
                "receipt_paths": self.paths,
            },
        }
        self.original = dual._production_blue_green_preflight_failure_receipt(
            cutover_id="cutover-pr1662-preflight", expected_head=self.HEAD,
            source_identity_sha256=self.SOURCE,
            error={"type": "ClientSnapshotError"}, observations=[],
        )

    def _install_receipt(self, document=None):
        import hashlib
        import json
        receipt = deepcopy(self.original if document is None else document)
        material = {k: v for k, v in receipt.items() if k != "receipt_sha256"}
        receipt["receipt_sha256"] = DEPLOY._sha256_json(material)
        cutover_path = self.cutovers / (receipt["cutover_id"] + ".json")
        cutover_path.write_text(json.dumps(receipt), encoding="utf-8")
        cutover_path.chmod(0o600)
        summary = self.runner._blue_green_summary({
            "receipt": receipt, "receipt_persisted": True,
            "receipt_path": str(cutover_path),
        })
        material = {
            "schema_version": 1,
            "kind": "grabowski_runtime_deploy_finalization",
            "unit": self.UNIT,
            "job_id": self.metadata["job_id"],
            "argv_sha256": self.metadata["argv_sha256"],
            "expected_head": self.HEAD,
            "receipt_paths": self.paths,
            "final_status": "failed",
            "completion_status": "failed",
            "repo_head": None, "release_id": None,
            "failure_type": "BlueGreenDeploymentIncomplete",
            "blue_green": summary,
            "blue_green_receipt_sha256": receipt["receipt_sha256"],
            "blind_retry_allowed": None,
        }
        payload = {**material, "payload_sha256": DEPLOY._sha256_json(material)}
        raw = json.dumps(payload, sort_keys=True).encode()
        file = self.entry / "finalization.json"
        file.write_bytes(raw)
        file.chmod(0o600)
        status = {
            "unit": self.UNIT, "metadata": self.metadata, "final_status": "failed",
            "finalization_receipt": {
                "valid": True, "state": "valid", "final_status": "failed",
                "expected_head": self.HEAD,
                "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                "payload_sha256": payload["payload_sha256"],
                "blue_green_receipt_sha256": receipt["receipt_sha256"],
                "blind_retry_allowed": None,
            },
        }
        return status, raw

    def _check(self, status, raw, *, bootstrap=False, reconcile=False):
        actual_loader = DEPLOY.midcutover.load_receipts
        with (
            mock.patch.object(DEPLOY.operator, "_read_job_metadata", return_value=self.metadata),
            mock.patch.object(DEPLOY.operator, "grabowski_job_status", return_value=status),
            mock.patch.object(DEPLOY.operator, "_jobs_root", return_value=self.jobs),
            mock.patch.object(DEPLOY.operator, "_read_finalization_receipt_file",
                              return_value={"ok": True, "raw": raw, "bytes": len(raw)}, create=True),
            mock.patch.object(DEPLOY.midcutover, "load_receipts",
                              side_effect=lambda: actual_loader(self.cutovers)),
        ):
            if bootstrap:
                return DEPLOY._bootstrap_deploy_index(self.jobs, read_only=True)["units"]
            if reconcile:
                with mock.patch.object(
                    DEPLOY, "_deploy_index",
                    return_value={"units": [self.UNIT], "pending_unit": None},
                ):
                    return DEPLOY._matching_inflight_deploy_job(
                        self.command, self.REPOSITORY
                    )
            return DEPLOY._verified_runtime_terminal_receipt(
                self.entry, self.metadata, self.command, status
            )

    def test_proven_failed_pre_cutover_does_not_reappear_on_bootstrap(self) -> None:
        status, raw = self._install_receipt()
        self.assertTrue(self._check(status, raw))
        self.assertEqual(self._check(status, raw, bootstrap=True), [])
        self.assertIsNone(self._check(status, raw, reconcile=True))

    def test_effectful_or_incomplete_pre_cutover_evidence_stays_blocking(self) -> None:
        cases = (
            ("blue_lost", ("recovery", "blue_preserved"), False),
            ("connector_started", ("recovery", "connector_switch_attempted"), True),
            ("action_drift", ("recovery", "action"), "readback_active_runtime_and_recover"),
            ("selector", ("selector_switch",), {"switched": True}),
            ("snapshot", ("snapshot_rebind",), {"receipt_sha256": "a" * 64}),
            ("readback", ("authoritative_readback",), {"authoritative": True}),
            ("readiness", ("green_readiness",), {"ready": True}),
            ("retirement", ("retirement",), {"done": True}),
            ("routing", ("final_routing",), {"selected_slot": "green"}),
            ("effect_terminalization", ("effect_terminalization",), {"done": True}),
            ("phase", ("phase",), "outcome_unknown"),
            ("outcome", ("outcome",), "outcome_unknown"),
        )
        for label, path, value in cases:
            with self.subTest(case=label):
                document = deepcopy(self.original)
                if len(path) == 2:
                    document[path[0]][path[1]] = value
                else:
                    document[path[0]] = value
                status, raw = self._install_receipt(document)
                self.assertFalse(self._check(status, raw))
                self.assertEqual(self._check(status, raw, bootstrap=True), [self.UNIT])

    def test_foreign_job_identity_or_missing_cutover_does_not_clear_reservation(self) -> None:
        status, raw = self._install_receipt()
        altered = deepcopy(self.metadata)
        altered["finalization_contract"]["expected_head"] = "f" * 40
        original = self.metadata
        try:
            self.metadata = altered
            self.assertFalse(self._check(status, raw))
        finally:
            self.metadata = original
        (self.cutovers / (self.original["cutover_id"] + ".json")).unlink()
        self.assertFalse(self._check(status, raw))


if __name__ == "__main__":
    unittest.main()

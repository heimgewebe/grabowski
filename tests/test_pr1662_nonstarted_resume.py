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
        # The reserved scheduled deploy uses the runtime-specific contract.
        # A generic job contract must never authorize this effect-bearing runner.
        metadata["finalization_contract"] = {
            "kind": "grabowski_runtime_deploy_finalization",
            "unit": self.UNIT,
            "job_id": metadata["job_id"],
            "argv_sha256": metadata["argv_sha256"],
            "expected_head": self.HEAD,
            "receipt_paths": {
                key: str(self.entry / filename)
                for key, filename in (
                    ("metadata", "metadata.json"),
                    ("stdout", "stdout.log"),
                    ("stderr", "stderr.log"),
                    ("finalization", "finalization.json"),
                )
            },
        }
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


class AmbiguousS0RecoveryHandoffTests(unittest.TestCase):
    """An unreadable cold snapshot is not an effect or permission to deploy."""

    def test_cold_unreadable_s0_can_only_yield_to_same_cutover_fresh_recovery(self) -> None:
        import json
        import sys
        import test_midcutover_resume as fixture
        tool_dir = Path(__file__).resolve().parents[1] / "tools"
        if str(tool_dir) not in sys.path:
            sys.path.insert(0, str(tool_dir))
        import run_midcutover_resume as resume_runner

        original = fixture.cutover_receipt()
        attempt = fixture.resume_receipt(
            resume_phase=DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT
        )
        binding = attempt["resume_binding"]
        attempt.update({
            "outcome": "outcome_unknown", "phase": "outcome_unknown",
            "snapshot_rebind": None, "pointer_promotion": None,
            "selector_switch": None, "canonical_operator": None,
            "retirement": None, "effect_terminalization": None,
            "final_routing": None,
            "admission_state": None, "final_state": None,
            "authoritative_readback": None,
            "recovery": {
                "action": "readback_active_runtime_and_recover",
                "automatic_rollback_forbidden": True,
                "blue_rollback_forbidden": True,
                "snapshot_binding_state": DEPLOY.midcutover.SNAPSHOT_BINDING_UNREADABLE,
                "snapshot_rebind_applied": False,
                "pointer_promoted": False, "canonical_selected": False,
                "snapshot_rollback_forbidden": False,
                "blind_retry_allowed": False,
                "fresh_classification_required": True,
                "error": {"type": "ColdSnapshotReadbackError"},
            },
        })
        attempt["receipt_sha256"] = DEPLOY._sha256_json({
            k: v for k, v in attempt.items() if k != "receipt_sha256"
        })
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jobs = root / "jobs"
            receipts_dir = root / "receipts"
            jobs.mkdir(mode=0o700)
            receipts_dir.mkdir(mode=0o700)
            unit = "grabowski-job-123a456b789c"
            entry = jobs / unit
            entry.mkdir(mode=0o700)
            for receipt in (original, attempt):
                name = receipt.get("cutover_id") or receipt["resume_id"]
                path = receipts_dir / (name + ".json")
                path.write_text(json.dumps(receipt), encoding="utf-8")
                path.chmod(0o600)
            summary = resume_runner._resume_summary({
                "receipt": attempt,
                "receipt_path": str(receipts_dir / (attempt["resume_id"] + ".json")),
                "receipt_persisted": True,
            })
            fields = {
                "cutover_id": original["cutover_id"],
                "expected_head": original["expected_head"],
                "repository": "/home/alex/repos/grabowski",
                "resume_binding_sha256": binding["binding_sha256"],
            }
            metadata = {"final_status": "failed"}
            status = {"final_status": "failed"}
            scheduled = {
                "repo": fields["repository"],
                "expected_head": fields["expected_head"],
                "cutover_id": fields["cutover_id"],
                "resume_binding_sha256": fields["resume_binding_sha256"],
            }
            loader = DEPLOY.midcutover.load_receipts
            with (
                mock.patch.object(DEPLOY.operator, "_jobs_root", return_value=jobs),
                mock.patch.object(DEPLOY, "_deploy_index",
                                  return_value={"units": [unit], "pending_unit": None}),
                mock.patch.object(DEPLOY, "_classify_indexed_job",
                                  return_value={"kind": "midcutover_resume",
                                                "terminal": False, "status": status,
                                                "metadata": metadata, "fields": fields}),
                mock.patch.object(DEPLOY, "_private_failed_resume_summary",
                                  return_value={"scheduled": scheduled, "summary": summary}),
                mock.patch.object(DEPLOY.midcutover, "load_receipts",
                                  side_effect=lambda: loader(receipts_dir)),
            ):
                self.assertTrue(
                    DEPLOY._indexed_failed_resume_is_noeffect_handoff(unit, binding),
                    "fresh S0 after unreadable cold readback must be recoverable",
                )
                self.assertFalse(
                    DEPLOY._indexed_failed_resume_is_noeffect_handoff(
                        unit, {**binding, "source_identity_sha256": "1" * 64}
                    )
                )
                with (
                    mock.patch.object(DEPLOY, "_classify_indexed_job",
                                      return_value={"kind": "deploy",
                                                    "terminal": False, "status": status,
                                                    "metadata": metadata, "fields": fields}),
                    mock.patch.object(DEPLOY, "_authenticated_scheduled_prerequisite_failure",
                                      return_value=(original, attempt, [original, attempt])),
                ):
                    self.assertTrue(
                        DEPLOY._indexed_failed_scheduled_resume_is_handoff(unit, binding),
                        "scheduled old S0 must yield to fresh exact recovery",
                    )
                with mock.patch.object(
                    DEPLOY, "_deploy_index",
                    return_value={"units": [unit], "pending_unit": unit},
                ):
                    self.assertFalse(
                        DEPLOY._indexed_failed_resume_is_noeffect_handoff(unit, binding)
                    )



class UnreadableS0RecoveryHandoffTests(unittest.TestCase):
    """A signed but effect-unconfirmed S0 attempt needs fresh recovery, not a deadlock."""

    REPO = Path("/home/alex/repos/grabowski")
    UNIT = "grabowski-job-aabbccdd0011"

    def setUp(self) -> None:
        import json
        import test_midcutover_resume as fixture
        import run_midcutover_resume as resume_runner

        self.fixture = fixture
        self.resume_runner = resume_runner
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.jobs = self.root / "jobs"
        self.cutovers = self.root / "cutovers"
        self.jobs.mkdir(mode=0o700)
        self.cutovers.mkdir(mode=0o700)
        self.entry = self.jobs / self.UNIT
        self.entry.mkdir(mode=0o700)

        # Exercise the real producer's S0 exception and unreadable cold
        # snapshot path rather than inventing an "outcome_unknown" receipt.
        runtime = fixture._FakeResumeRuntime(
            phase=DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT,
            fail_phase="rebind_snapshot_before_write",
        )
        runtime.cold_snapshot_observation = lambda: {
            "state": DEPLOY.midcutover.SNAPSHOT_BINDING_UNREADABLE,
            "error": "temporary readback failure",
        }
        # A real S0 starts with the prior post-switch selector still on green.
        # The generic fake defaults to canonical for later-phase tests.
        runtime.current_selector.update({
            "selected_slot": "green",
            "upstream_port": DEPLOY.midcutover.GREEN_UPSTREAM_PORT,
            "selector_sha256": fixture.SELECTOR_SHA256,
            "generation": fixture.GENERATION,
        })
        produced = fixture.ResumeEffectSemanticsTests()._run(
            runtime, self.cutovers
        )
        self.assertEqual(produced["outcome"], "outcome_unknown")
        self.attempt = produced["receipt"]
        self.assertIsNone(self.attempt["snapshot_rebind"])
        self.assertEqual(self.attempt["resume_phase"], DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT)
        recovery = self.attempt["recovery"]
        for key in ("snapshot_rebind_applied", "pointer_promoted", "canonical_selected"):
            self.assertIs(recovery[key], False)
        self.assertEqual(
            recovery["snapshot_binding_state"],
            DEPLOY.midcutover.SNAPSHOT_BINDING_UNREADABLE,
        )
        self.old_binding = self.attempt["resume_binding"]
        self.command = DEPLOY._midcutover_resume_command(
            self.REPO,
            self.REPO / DEPLOY.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH,
            fixture.HEAD_GREEN,
            fixture.CUTOVER_ID,
            self.old_binding["binding_sha256"],
        )
        self.meta = {
            "unit": self.UNIT,
            "job_id": self.UNIT.removeprefix("grabowski-job-"),
            "argv": self.command,
            "argv_sha256": DEPLOY._deploy_command_sha256(self.command),
            "cwd": str(self.REPO),
            "final_status": "failed",
        }
        self.status = {"final_status": "failed"}
        self._install_attempt(self.attempt)

    def _install_attempt(self, receipt) -> None:
        import json

        path = self.cutovers / (receipt["resume_id"] + ".json")
        path.write_text(json.dumps(receipt), encoding="utf-8")
        path.chmod(0o600)
        summary = self.resume_runner._resume_summary({
            "receipt": receipt,
            "receipt_persisted": True,
            "receipt_path": str(path),
        })
        events = [
            {
                "timestamp_unix": 1001,
                "phase": "midcutover-resume-scheduled",
                "repo": str(self.REPO),
                "expected_head": self.fixture.HEAD_GREEN,
                "cutover_id": self.fixture.CUTOVER_ID,
                "resume_binding_sha256": self.old_binding["binding_sha256"],
            },
            {"timestamp_unix": 1002, "phase": "midcutover-resume-receipt", **summary},
            {
                "timestamp_unix": 1003,
                "phase": "midcutover-resume-incomplete",
                "outcome": receipt["outcome"],
            },
        ]
        stdout = self.entry / "stdout.log"
        stdout.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
        stdout.chmod(0o600)

    def _with_evidence(self, fresh_binding, *, pending=False) -> bool:
        real_loader = DEPLOY.midcutover.load_receipts
        with (
            mock.patch.object(DEPLOY.operator, "_jobs_root", return_value=self.jobs),
            mock.patch.object(DEPLOY.operator, "_read_job_metadata", return_value=self.meta),
            mock.patch.object(DEPLOY.operator, "grabowski_job_status", return_value=self.status),
            mock.patch.object(
                DEPLOY, "_deploy_index",
                return_value={
                    "units": [self.UNIT],
                    "pending_unit": self.UNIT if pending else None,
                },
            ),
            mock.patch.object(
                DEPLOY.midcutover, "load_receipts",
                side_effect=lambda: real_loader(self.cutovers),
            ),
        ):
            return DEPLOY._indexed_failed_resume_is_noeffect_handoff(
                self.UNIT, fresh_binding
            )

    def _terminal_with_evidence(self) -> bool:
        real_loader = DEPLOY.midcutover.load_receipts
        with mock.patch.object(
            DEPLOY.midcutover, "load_receipts",
            side_effect=lambda: real_loader(self.cutovers),
        ):
            return DEPLOY._verified_runtime_terminal_receipt(
                self.entry, self.meta, self.command, self.status
            )

    def _rewrite_proven_attempt(self, *, key, value, recovery=False) -> None:
        mutated = deepcopy(self.attempt)
        if recovery:
            mutated["recovery"][key] = value
        else:
            mutated[key] = value
        mutated["receipt_sha256"] = DEPLOY._sha256_json({
            k: v for k, v in mutated.items() if k != "receipt_sha256"
        })
        self._install_attempt(mutated)

    def test_unreadable_s0_requires_fresh_same_cutover_s0_or_s1_handoff(self):
        self.assertFalse(self._terminal_with_evidence(), "a failed S0 is not completed deployment")
        fresh_s0 = self.old_binding
        fresh_s1 = self.fixture.resume_receipt(
            resume_phase=DEPLOY.midcutover.PHASE_PROMOTE_POINTER
        )["resume_binding"]
        fresh_s2 = self.fixture.resume_receipt(
            resume_phase=DEPLOY.midcutover.PHASE_SELECT_CANONICAL
        )["resume_binding"]
        self.assertTrue(self._with_evidence(fresh_s0))
        self.assertTrue(self._with_evidence(fresh_s1))
        self.assertTrue(self._with_evidence(fresh_s2))
        self.assertFalse(self._with_evidence(fresh_s0, pending=True))
        self.assertFalse(self._with_evidence({**fresh_s0, "source_identity_sha256": "f" * 64}))
        # Ordinary deployment can retire the failed attempt only AFTER an
        # independently authentic completed resume resolves its original cutover.
        final = self.fixture.resume_receipt(resume_id="bgcr-pr1662-recovery-terminal")
        path = self.cutovers / (final["resume_id"] + ".json")
        import json
        path.write_text(json.dumps(final), encoding="utf-8")
        path.chmod(0o600)
        self.assertTrue(self._terminal_with_evidence())

    def test_s0_unknown_without_exact_no_effect_proof_does_not_handoff(self):
        self.assertFalse(DEPLOY._progressed_resume_has_authentic_recovery_evidence(
            self.attempt, self.resume_runner._resume_summary({
                "receipt": self.attempt,
                "receipt_persisted": True,
                "receipt_path": str(self.cutovers / (self.attempt["resume_id"] + ".json")),
            })
        ))
        for key, value, recovery in (
            ("snapshot_rebind", {"rebound": True}, False),
            ("pointer_promotion", {"promoted": True}, False),
            ("selector_switch", {"switched": True}, False),
            ("effect_terminalization", {"blocking_tool_calls": 0}, False),
            ("authoritative_readback", {
                "authoritative": True,
                "selector": {"selected_slot": "canonical"},
                "ingress": {"selected_slot": "canonical"},
            }, False),
            ("snapshot_binding_state", DEPLOY.midcutover.SNAPSHOT_BINDING_FOREIGN, True),
            ("action", "reclassify_and_retry_resume", True),
            ("fresh_classification_required", False, True),
            ("next_resume_phase", DEPLOY.midcutover.PHASE_PROMOTE_POINTER, True),
        ):
            with self.subTest(key=key):
                self._rewrite_proven_attempt(key=key, value=value, recovery=recovery)
                self.assertFalse(self._with_evidence(self.old_binding))
                self._install_attempt(self.attempt)
        stdout = self.entry / "stdout.log"
        stdout.write_text('{"phase":"midcutover-resume-scheduled"}\n', encoding="utf-8")
        self.assertFalse(self._with_evidence(self.old_binding))


class PreparedResumeBindingDriftTests(unittest.TestCase):
    """A queued old binding can be refused before effects while the same cutover advances."""

    def test_authentic_binding_drift_refusal_yields_only_to_recovery_and_later_terminal(self):
        import json
        import test_midcutover_resume as fixture
        from contextlib import nullcontext

        dual = fixture.dual
        for phase in (
            DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT,
            DEPLOY.midcutover.PHASE_PROMOTE_POINTER,
        ):
            with self.subTest(phase=phase):
                # Reuse the real job-dir/stdout receipt fixture, not a fabricated
                # private-failure status or a mocked classifier gate.
                job = UnreadableS0RecoveryHandoffTests()
                job.setUp()
                self.addCleanup(job.temp.cleanup)
                (job.cutovers / (job.attempt["resume_id"] + ".json")).unlink()
                original_authorized = fixture.resume_receipt(
                    resume_phase=DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT
                )["resume_binding"]
                if phase == DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT:
                    newly_classified = deepcopy(original_authorized)
                    newly_classified["source_evidence_time"] += 1
                    newly_classified["binding_sha256"] = DEPLOY._sha256_json({
                        k: v for k, v in newly_classified.items()
                        if k != "binding_sha256"
                    })
                else:
                    newly_classified = fixture.resume_receipt(
                        resume_phase=phase
                    )["resume_binding"]
                self.assertIsNotNone(
                    DEPLOY.midcutover._validated_resume_binding(newly_classified)
                )
                fresh = {
                    "schema_version": DEPLOY.midcutover.SCHEMA_VERSION,
                    "kind": DEPLOY.midcutover.KIND,
                    "lane": DEPLOY.midcutover.LANE_MID_CUTOVER_RESUME,
                    "resume_binding": newly_classified,
                    "evidence": {
                        "snapshot_binding_state": newly_classified["snapshot_binding_state"],
                    },
                    "classification_sha256": "d" * 64,
                }
                refused = {
                    **fresh,
                    "lane": DEPLOY.midcutover.LANE_FAIL_CLOSED,
                    "reasons": ["resume_binding_drifted"],
                    "authorized_resume_binding_sha256": original_authorized["binding_sha256"],
                }
                with (
                    mock.patch.object(dual.core, "deployment_lock", return_value=nullcontext()),
                    mock.patch.object(
                        dual, "prepare_midcutover_resume_runtime",
                        side_effect=dual.MidCutoverResumeDenied(refused),
                    ),
                    mock.patch.object(
                        dual, "classify_midcutover_resume", return_value=fresh,
                    ),
                    mock.patch.object(dual, "BLUE_GREEN_RECEIPT_ROOT", job.cutovers),
                ):
                    result = dual.resume_production_blue_green_cutover(
                        repo=job.REPO, expected_head=fixture.HEAD_GREEN,
                        resume_id=(
                            "bgcr-pr1662-binding-drift-s0"
                            if phase == DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT
                            else "bgcr-pr1662-binding-drift-s1"
                        ),
                        require_resume_binding_sha256=original_authorized["binding_sha256"],
                    )
                self.assertNotEqual(
                    result["receipt"]["resume_binding_sha256"],
                    original_authorized["binding_sha256"],
                )
                job.old_binding = original_authorized
                job.command = DEPLOY._midcutover_resume_command(
                    job.REPO,
                    job.REPO / DEPLOY.MIDCUTOVER_RESUME_RUNNER_RELATIVE_PATH,
                    fixture.HEAD_GREEN,
                    fixture.CUTOVER_ID,
                    original_authorized["binding_sha256"],
                )
                job.meta["argv"] = job.command
                job.meta["argv_sha256"] = DEPLOY._deploy_command_sha256(job.command)
                job.attempt = result["receipt"]
                job._install_attempt(job.attempt)
                self.assertFalse(job._terminal_with_evidence())
                self.assertTrue(job._with_evidence(newly_classified))
                self.assertFalse(job._with_evidence({
                    **newly_classified,
                    "source_identity_sha256": "f" * 64,
                }))
                tampered = deepcopy(job.attempt)
                tampered["recovery"]["error"]["initial_classification"][
                    "authorized_resume_binding_sha256"
                ] = "f" * 64
                tampered["receipt_sha256"] = DEPLOY._sha256_json({
                    k: v for k, v in tampered.items() if k != "receipt_sha256"
                })
                job._install_attempt(tampered)
                self.assertFalse(job._with_evidence(newly_classified))
                job._install_attempt(job.attempt)
                # Never terminal before completed lineage, even on verified no-effect refusal.
                final = fixture.resume_receipt(
                    resume_id=(
                        "bgcr-pr1662-drift-s0-final"
                        if phase == DEPLOY.midcutover.PHASE_REBIND_SNAPSHOT
                        else "bgcr-pr1662-drift-s1-final"
                    )
                )
                final_path = job.cutovers / (final["resume_id"] + ".json")
                final_path.write_text(json.dumps(final), encoding="utf-8")
                final_path.chmod(0o600)
                self.assertTrue(job._terminal_with_evidence())


if __name__ == "__main__":
    unittest.main()
"""PR1662 P1: an exited prerequisite resume cannot block its own recovery."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_self_deploy as source
import test_midcutover_resume as fixture

SD = source.SELF_DEPLOY
RUNNER = source.RUNNER


class ScheduledPrerequisiteResumeFailure(unittest.TestCase):
    def test_persisted_failed_prerequisite_resume_is_recovery_only(self):
        phases = SD.midcutover.RESUME_PHASES
        # A no-effect S0 job remains indexed even after another authentic
        # retry advances S0. Every later freshly classified phase must still
        # be eligible for recovery, never for ordinary deployment.
        cases = tuple((False, phases[0], phase) for phase in phases) + tuple(
            (True, phases[index], phases[index + 1])
            for index in range(len(phases) - 1)
        )
        for progressed, prior_phase, next_phase in cases:
            with self.subTest(
                progressed=progressed, previous=prior_phase, current=next_phase
            ), tempfile.TemporaryDirectory() as tmp:
                original = fixture.cutover_receipt()
                attempt = fixture.resume_receipt(resume_phase=prior_phase)
                old = attempt["resume_binding"]
                if progressed:
                    attempt.update({
                        "outcome": "outcome_unknown",
                        "phase": "outcome_unknown",
                        "snapshot_rebind": {"rebound": True, "receipt_sha256": "ab" * 32},
                        "recovery": {
                            "action": "readback_active_runtime_and_recover",
                            "automatic_rollback_forbidden": True,
                            "blue_rollback_forbidden": True,
                            "snapshot_rebind_applied": True,
                            "fresh_classification_required": True,
                            "blind_retry_allowed": False,
                        },
                    })
                    current = fixture.resume_receipt(
                        resume_phase=next_phase
                    )["resume_binding"]
                    failure = "MidCutoverResumeOutcomeUnknown"
                else:
                    attempt.update({
                        "outcome": "failed_pre_resume",
                        "phase": "failed_pre_resume",
                        "recovery": {
                            "action": "reclassify_and_retry_resume",
                            "blue_green_state_unchanged": True,
                            "fresh_classification_required": True,
                            "blind_retry_allowed": False,
                        },
                    })
                    for key in (
                        "snapshot_rebind", "pointer_promotion", "selector_switch",
                        "canonical_operator", "retirement", "final_routing",
                        "effect_terminalization",
                    ):
                        attempt[key] = None
                    current = fixture.resume_receipt(
                        resume_phase=next_phase
                    )["resume_binding"]
                    failure = "MidCutoverResumeFailedPreResume"
                attempt["receipt_sha256"] = SD._sha256_json({
                    k: v for k, v in attempt.items() if k != "receipt_sha256"
                })

                home = Path(tmp)
                jobs, receipts_dir = home / "jobs", home / "cutovers"
                jobs.mkdir(mode=0o700)
                receipts_dir.mkdir(mode=0o700)
                unit = "grabowski-job-123412341234"
                entry = jobs / unit
                entry.mkdir(mode=0o700)
                for value, key in ((original, "cutover_id"), (attempt, "resume_id")):
                    path = receipts_dir / (value[key] + ".json")
                    path.write_text(json.dumps(value), encoding="utf-8")
                    path.chmod(0o600)
                if not progressed and next_phase != phases[0]:
                    # Real persisted later progressed attempt for the *same*
                    # original cutover; this is not a fabricated completed
                    # lineage and cannot itself terminalize the old S0 job.
                    progressed_attempt = fixture.resume_receipt(
                        resume_id="bgcr-followup-progressed-after-noeffect-s0",
                        resume_phase=phases[0],
                    )
                    progressed_attempt.update({
                        "outcome": "outcome_unknown",
                        "phase": "outcome_unknown",
                        "snapshot_rebind": {
                            "rebound": True, "receipt_sha256": "a1" * 32,
                        },
                        "recovery": {
                            "action": "readback_active_runtime_and_recover",
                            "automatic_rollback_forbidden": True,
                            "blue_rollback_forbidden": True,
                            "snapshot_rebind_applied": True,
                            "fresh_classification_required": True,
                            "blind_retry_allowed": False,
                        },
                    })
                    progressed_attempt["receipt_sha256"] = SD._sha256_json({
                        k: v for k, v in progressed_attempt.items()
                        if k != "receipt_sha256"
                    })
                    progressed_path = receipts_dir / (
                        progressed_attempt["resume_id"] + ".json"
                    )
                    progressed_path.write_text(
                        json.dumps(progressed_attempt), encoding="utf-8"
                    )
                    progressed_path.chmod(0o600)
                attempt_path = receipts_dir / (attempt["resume_id"] + ".json")
                repo = SD.CANONICAL_REPOSITORY
                command = SD._deploy_command(
                    repo, repo / SD.RUNNER_RELATIVE_PATH, fixture.HEAD_GREEN, 8,
                    source_identity_sha256=fixture.SOURCE_IDENTITY_SHA256,
                )
                argv_hash = SD._deploy_command_sha256(command)
                paths = {name: str(entry / namefile) for name, namefile in (
                    ("metadata", "metadata.json"), ("stdout", "stdout.log"),
                    ("stderr", "stderr.log"), ("finalization", "finalization.json"),
                )}
                meta = {
                    "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                    "argv": command, "argv_sha256": argv_hash, "cwd": str(repo),
                    "final_status": "launch_submitted",
                    "finalization_contract": {
                        "kind": "grabowski_runtime_deploy_finalization",
                        "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                        "argv_sha256": argv_hash, "expected_head": fixture.HEAD_GREEN,
                        "receipt_paths": paths,
                    },
                }
                material = {
                    "schema_version": 1, "kind": "grabowski_runtime_deploy_finalization",
                    "unit": unit, "job_id": meta["job_id"],
                    "argv_sha256": argv_hash, "expected_head": fixture.HEAD_GREEN,
                    "receipt_paths": paths, "final_status": "failed",
                    "completion_status": "failed", "repo_head": None,
                    "release_id": None, "failure_type": failure,
                    "blue_green": None, "blue_green_receipt_sha256": None,
                    "blind_retry_allowed": None, "timestamp_unix": 1000,
                }
                payload = {**material, "payload_sha256": SD._sha256_json(material)}
                raw = json.dumps(payload, sort_keys=True).encode()
                status = {
                    "final_status": "failed",
                    "finalization_receipt": {
                        "valid": True, "state": "valid", "final_status": "failed",
                        "expected_head": fixture.HEAD_GREEN,
                        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
                        "payload_sha256": payload["payload_sha256"],
                        "blue_green_receipt_sha256": None,
                        "blind_retry_allowed": None,
                    },
                }
                schedule = {
                    "phase": "scheduled", "timestamp_unix": 1000,
                    "repo": str(repo), "canonical_repo": str(repo),
                    "source_kind": "canonical-main",
                    "source_identity_sha256": fixture.SOURCE_IDENTITY_SHA256,
                    "expected_head": fixture.HEAD_GREEN, "delay_seconds": 8,
                }
                decision = {
                    "phase": "recovery-classification", "timestamp_unix": 1001,
                    "lane": SD.midcutover.LANE_MID_CUTOVER_RESUME,
                    "resume_required": True, "deploy_allowed": False,
                    "execution_head": fixture.HEAD_GREEN,
                    "resume_target_head": fixture.HEAD_GREEN,
                    "resume_phase": old["resume_phase"],
                    "cutover_id": fixture.CUTOVER_ID,
                    "resume_binding_sha256": old["binding_sha256"],
                    "classification_sha256": "2" * 64,
                }
                summary = {
                    "schema_version": 1,
                    "kind": "grabowski_scheduled_midcutover_resume_summary",
                    "receipt_sha256": attempt["receipt_sha256"],
                    "receipt_path": str(attempt_path),
                    "outcome": attempt["outcome"],
                    "resume_phase": attempt["resume_phase"],
                    "resumed_cutover_id": fixture.CUTOVER_ID,
                    "resume_target_head": fixture.HEAD_GREEN,
                    "execution_head": fixture.HEAD_GREEN,
                }
                summary["summary_sha256"] = SD._sha256_json(summary)
                terminal = {
                    "phase": "midcutover-recovery-terminal", "timestamp_unix": 1003,
                    "resume_outcome": attempt["outcome"], "failure_type": failure,
                    "resume_target_head": fixture.HEAD_GREEN,
                    "execution_head": fixture.HEAD_GREEN,
                    "requested_head_deployment_performed": False,
                    "effect_applied": progressed,
                    "retry_requires_reclassification": True,
                    "receipt_sha256": attempt["receipt_sha256"],
                    "authority": "durable mid-cutover resume receipt",
                }
                events = [
                    schedule, decision,
                    {"phase": "midcutover-resume-receipt", "timestamp_unix": 1002, **summary},
                    terminal,
                ]
                output = entry / "stdout.log"
                output.write_text("".join(json.dumps(item)+"\n" for item in events), encoding="utf-8")
                output.chmod(0o600)
                fields = SD._deploy_command_fields(command)
                self.assertIsNotNone(fields)
                loader = SD.midcutover.load_receipts
                classified = {
                    "kind": "deploy", "terminal": False,
                    "metadata": meta, "status": status, "fields": fields,
                }
                with (
                    mock.patch.object(SD.operator, "_jobs_root", return_value=jobs),
                    mock.patch.object(SD, "_deploy_index", return_value={
                        "units": [unit], "pending_unit": None,
                    }),
                    mock.patch.object(SD, "_classify_indexed_job", return_value=classified),
                    mock.patch.object(SD.operator, "_read_finalization_receipt_file",
                                      return_value={"ok": True, "raw": raw}, create=True),
                    mock.patch.object(SD.midcutover, "load_receipts",
                                      side_effect=lambda: loader(receipts_dir)),
                ):
                    self.assertFalse(SD._verified_runtime_terminal_receipt(
                        entry, meta, command, status
                    ), "open recovery is not complete deployment")
                    self.assertTrue(SD._indexed_failed_scheduled_resume_is_handoff(
                        unit, current
                    ), "exact scheduled runner failure must yield to its own recovery")
                    self.assertFalse(SD._indexed_failed_scheduled_resume_is_handoff(
                        unit, {**current, "source_identity_sha256": "1" * 64}
                    ), "foreign source must remain blocked")
                    # Both the exact private finalization and the complete
                    # runner stdout are required, not just a failed process.
                    with mock.patch.object(
                        SD.operator, "_read_finalization_receipt_file",
                        return_value={"ok": True, "raw": b"{}"}, create=True,
                    ):
                        self.assertFalse(SD._indexed_failed_scheduled_resume_is_handoff(
                            unit, current
                        ), "tampered private finalization must remain a blocker")
                    output.write_text(
                        "".join(json.dumps(item)+"\n" for item in events[:-1]),
                        encoding="utf-8",
                    )
                    self.assertFalse(SD._indexed_failed_scheduled_resume_is_handoff(
                        unit, current
                    ), "missing final event cannot attach the receipt to this job")
                    output.write_text(
                        "".join(json.dumps(item)+"\n" for item in events),
                        encoding="utf-8",
                    )
                    foreign = fixture.cutover_receipt(
                        cutover_id="bgc-unrelated-open-scheduled"
                    )
                    foreign_path = receipts_dir / (foreign["cutover_id"] + ".json")
                    foreign_path.write_text(json.dumps(foreign), encoding="utf-8")
                    foreign_path.chmod(0o600)
                    self.assertFalse(SD._indexed_failed_scheduled_resume_is_handoff(
                        unit, current
                    ), "one authenticated recovery cannot hide another open lineage")
                    foreign_path.unlink()
                    with mock.patch.object(SD, "_deploy_index", return_value={
                        "units": [unit], "pending_unit": unit,
                    }):
                        self.assertFalse(SD._indexed_failed_scheduled_resume_is_handoff(
                            unit, current
                        ))
                    if progressed:
                        stale_s0 = fixture.resume_receipt(
                            resume_phase=SD.midcutover.PHASE_REBIND_SNAPSHOT
                        )["resume_binding"]
                        self.assertFalse(SD._indexed_failed_scheduled_resume_is_handoff(
                            unit, stale_s0
                        ), "progressed recovery cannot blindly restart at S0")
                    completed = fixture.resume_receipt(
                        resume_id="bgcr-final-prerequisite-test"
                    )
                    settled_path = receipts_dir / (completed["resume_id"] + ".json")
                    settled_path.write_text(json.dumps(completed), encoding="utf-8")
                    settled_path.chmod(0o600)
                    self.assertTrue(SD._verified_runtime_terminal_receipt(
                        entry, meta, command, status
                    ), "later completed exact lineage must retire failed prerequisite job")


if __name__ == "__main__":
    unittest.main()
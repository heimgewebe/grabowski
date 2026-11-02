"""Reproductions of independent Grok 4.7 P1/P2 findings on PR #1662.

Each test must fail on the vulnerable c807984 head before the fix.
"""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_midcutover_resume as fixture
import test_pr1662_successor_terminal as successor
import test_pr1662_recovery_predecessor as predecessor
import test_provenance_recovery as recover_fixture
import test_self_deploy as source

SD = source.SELF_DEPLOY
RECOVERY = recover_fixture.provenance_recovery


class GrokIndependentReviewRegressions(unittest.TestCase):
    def test_blue_rollback_requires_blue_revision_not_just_equal_channels(self):
        case = successor.PublicationRollbackTerminalProofTests(
            "test_actual_effect_free_and_verified_rollback_are_terminal"
        )
        case.setUp()
        self.assertTrue(SD._signed_clean_blue_rollback_is_terminal(
            case.original, [case.original]
        ))
        altered = copy.deepcopy(case.original)
        readback = altered["authoritative_readback"]
        for channel in ("selector", "ingress"):
            readback[channel]["repo_head"] = "f" * 40
        readback["readback_sha256"] = SD._sha256_json({
            k: v for k, v in readback.items() if k != "readback_sha256"
        })
        altered["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in altered.items() if k != "receipt_sha256"
        })
        self.assertFalse(
            SD._signed_clean_blue_rollback_is_terminal(altered, [altered]),
            "hash-valid readback on a foreign blue revision is not a clean rollback",
        )

    def test_resumed_successor_requires_canonical_ingress_not_green(self):
        case = successor.CompletedSuccessorTerminalTests(
            "test_authentic_completed_resume_can_settle_predecessor_a"
        )
        case.setUp()
        _a, b, resumed, _fields = case._recovering_successor()
        fields = {
            "expected_head": b["expected_head"],
            "source_identity_sha256": b["source_identity_sha256"],
        }
        self.assertTrue(SD._completed_resumed_successor_routing_is_authentic(
            b, [b, resumed], fields
        ))
        altered = copy.deepcopy(resumed)
        readback = altered["authoritative_readback"]
        readback["ingress"]["selected_slot"] = "green"
        readback["readback_sha256"] = SD._sha256_json({
            k: v for k, v in readback.items() if k != "readback_sha256"
        })
        altered["receipt_sha256"] = SD._sha256_json({
            k: v for k, v in altered.items() if k != "receipt_sha256"
        })
        self.assertFalse(
            SD._completed_resumed_successor_routing_is_authentic(
                b, [b, altered], fields
            ),
            "an authenticated completed resume with ingress still on green cannot settle",
        )

    def test_prerequisite_completed_claim_must_be_unique_in_full_inventory(self):
        original = fixture.cutover_receipt()
        completed = fixture.resume_receipt()
        extra = fixture.resume_receipt(
            resume_id="bgcr-second-completed-claim-against-same-b"
        )
        expected_head = "a" * 40
        material = {
            "schema_version": 1,
            "kind": "grabowski_resolved_midcutover_prerequisite",
            "resumed_cutover_id": completed["resumed_cutover_id"],
            "resume_receipt_sha256": completed["receipt_sha256"],
            "execution_head": expected_head,
        }
        reason = "MidCutoverPrerequisiteRecovered:" + SD._sha256_json(material)
        with mock.patch.object(SD.midcutover, "load_receipts", return_value={
            "receipts": [original, completed], "unreadable": [], "present": True,
        }):
            self.assertTrue(SD._authentic_completed_cutover_remains_settled(
                reason, expected_head
            ))
        with mock.patch.object(SD.midcutover, "load_receipts", return_value={
            "receipts": [original, completed, extra], "unreadable": [], "present": True,
        }):
            self.assertFalse(SD._authentic_completed_cutover_remains_settled(
                reason, expected_head
            ), "two completed resumes of one cutover are ambiguous")

    def test_predecessor_allows_signed_scheduled_b_resume_without_original_deploy_job(self):
        case = predecessor.RecoveredSuccessorPredecessorTests(
            "test_authentic_incomplete_b_allows_only_its_exact_predecessor_handoff"
        )
        case.setUp()
        a, b = predecessor.A_UNIT, predecessor.B_UNIT
        with (
            mock.patch.object(RECOVERY, "self_deploy", SD),
            mock.patch.object(SD, "inflight_runtime_job_evidence",
                return_value={
                    "blocking_units": [a, b], "inflight_units": [a, b],
                    "idempotent_match": None, "ambiguous_identical_units": [],
                    "pruned_units": [], "stale_pending_reconciliation": None,
                    "deploy_index_mutation": None, "error": None,
                }),
            mock.patch.object(SD,
                "_indexed_failed_deploy_is_cutover_handoff", return_value=False),
            mock.patch.object(SD,
                "_indexed_failed_resume_is_noeffect_handoff", return_value=False),
            mock.patch.object(SD,
                "_indexed_failed_scheduled_resume_is_handoff",
                side_effect=lambda unit, binding: unit == b),
            mock.patch.object(SD,
                "_indexed_completed_predecessor_is_recovery_handoff",
                side_effect=lambda unit, binding: unit == a),
        ):
            result = RECOVERY._competing_deployment_evidence(
                resume_binding=case.binding
            )
        self.assertEqual(result["inflight_deploy_jobs"], [],
                         "authenticated scheduled B is sufficient for A to yield")
        self.assertEqual(result["recovery_handoff_units"], [a, b])

    def test_cold_bootstrap_uses_same_proven_terminal_classifier_as_warm_index(self):
        with tempfile.TemporaryDirectory(prefix="pr1662-grok-cold-") as temp:
            root = Path(temp) / "jobs"
            root.mkdir()
            unit = "grabowski-job-a12233445566"
            (root / unit).mkdir(mode=0o700)
            repo = Path("/home/alex/repos/grabowski")
            argv = SD._deploy_command(
                repo, repo / SD.RUNNER_RELATIVE_PATH, "a" * 40, 8,
                source_identity_sha256=fixture.SOURCE_IDENTITY_SHA256,
            )
            metadata = {
                "unit": unit, "job_id": unit.removeprefix("grabowski-job-"),
                "argv": argv, "argv_sha256": SD._deploy_command_sha256(argv),
                "cwd": str(repo), "final_status": "launch_submitted",
            }
            with (
                mock.patch.object(SD.operator, "_read_job_metadata",
                    return_value=metadata),
                mock.patch.object(SD.operator, "grabowski_job_status",
                    return_value={"final_status": "succeeded"}),
                mock.patch.object(SD, "_deploy_finalization_retry_block",
                    return_value=False),
                mock.patch.object(SD, "_verified_runtime_terminal_receipt",
                    return_value=False),
                mock.patch.object(SD, "_classify_indexed_job",
                    return_value={"terminal": True}) as classify,
            ):
                result = SD._bootstrap_deploy_index(root, read_only=True)
            self.assertEqual(result["units"], [],
                 "cold bootstrap must not retain a warm-classifier terminal job")
            classify.assert_called_once()


if __name__ == "__main__":
    unittest.main()

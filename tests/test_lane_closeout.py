from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_lane_closeout as closeout


BASE = "a" * 40
HEAD = "b" * 40
MERGED = "c" * 40


class LaneCloseoutTests(unittest.TestCase):
    def observation(self, **overrides):
        values = {
            "lane_id": "lane-1",
            "repository": "/tmp/repo",
            "workspace": "/tmp/worktree",
            "branch": "feat/lane-1",
            "base_revision": BASE,
            "writer_state": "completed",
            "task_active": False,
            "process_active": False,
            "lease_active": True,
            "git_dirty": False,
            "head_sha": HEAD,
            "remote_head_sha": HEAD,
            "ahead_commits": 0,
            "behind_commits": 0,
        }
        values.update(overrides)
        return closeout.LaneCloseoutObservation(**values)

    def test_active_writer_is_not_closed(self) -> None:
        result = closeout.classify(
            self.observation(writer_state="running", task_active=True)
        )
        self.assertEqual(result["phase"], "active")
        self.assertIsNone(result["closeout_state"])
        self.assertFalse(result["lease_release_ready"])

    def test_exact_open_pr_is_terminal(self) -> None:
        result = closeout.classify(
            self.observation(
                pr_number=631,
                pr_state="open",
                pr_head_sha=HEAD,
                pr_origin="opened",
            )
        )
        self.assertEqual(result["closeout_state"], "pr_opened")
        self.assertTrue(result["lease_release_ready"])

    def test_existing_pr_update_is_distinguished(self) -> None:
        result = closeout.classify(
            self.observation(
                pr_number=631,
                pr_state="open",
                pr_head_sha=HEAD,
                pr_origin="updated",
            )
        )
        self.assertEqual(result["closeout_state"], "pr_updated")

    def test_dirty_terminal_writer_requires_rescue(self) -> None:
        result = closeout.classify(
            self.observation(
                writer_state="failed",
                git_dirty=True,
                remote_head_sha=BASE,
                ahead_commits=0,
            )
        )
        self.assertEqual(result["phase"], "rescue_required")
        self.assertIn("valuable_dirty_state", result["reason_codes"])
        self.assertEqual(
            result["recovery_actions"][0], "preserve_workspace_and_leases"
        )
        self.assertIn("bind_successor_controller", result["recovery_actions"])
        self.assertFalse(result["lease_release_ready"])

    def test_unpushed_commit_requires_push_and_pr(self) -> None:
        result = closeout.classify(
            self.observation(remote_head_sha=BASE, ahead_commits=1)
        )
        self.assertIn("unpushed_commits", result["reason_codes"])
        self.assertIn("push_exact_branch_head", result["recovery_actions"])
        self.assertIn("create_or_update_pr", result["recovery_actions"])

    def test_candidate_adopted_is_terminal_before_push_or_pr(self) -> None:
        result = closeout.classify(
            self.observation(
                remote_head_sha=BASE,
                ahead_commits=1,
                candidate_id="d" * 64,
                adoption_receipt_sha256="e" * 64,
                adoption_commit_sha=HEAD,
            )
        )
        self.assertEqual(result["phase"], "terminal")
        self.assertEqual(result["closeout_state"], "candidate_adopted")
        self.assertEqual(result["reason_codes"], ["candidate_adoption_receipt_bound"])
        self.assertTrue(result["lease_release_ready"])
        self.assertFalse(result["workspace_cleanup_ready"])

    def test_delivery_closeout_precedes_candidate_adoption_when_already_observed(self) -> None:
        adoption = {
            "candidate_id": "d" * 64,
            "adoption_receipt_sha256": "e" * 64,
            "adoption_commit_sha": HEAD,
        }
        merged = closeout.classify(
            self.observation(
                pr_state="merged",
                pr_number=631,
                pr_head_sha=HEAD,
                merged_sha=HEAD,
                **adoption,
            )
        )
        self.assertEqual(merged["closeout_state"], "pr_merged")

        deployed = closeout.classify(
            self.observation(
                pr_state="merged",
                pr_number=631,
                pr_head_sha=HEAD,
                merged_sha=HEAD,
                deployed_sha=HEAD,
                **adoption,
            )
        )
        self.assertEqual(deployed["closeout_state"], "deployed")

    def test_candidate_adoption_requires_exact_clean_adopted_head(self) -> None:
        mismatch = closeout.classify(
            self.observation(
                head_sha="f" * 40,
                remote_head_sha=BASE,
                ahead_commits=1,
                candidate_id="d" * 64,
                adoption_receipt_sha256="e" * 64,
                adoption_commit_sha=HEAD,
            )
        )
        self.assertNotEqual(mismatch.get("closeout_state"), "candidate_adopted")
        self.assertFalse(mismatch["lease_release_ready"])

        dirty = closeout.classify(
            self.observation(
                git_dirty=True,
                candidate_id="d" * 64,
                adoption_receipt_sha256="e" * 64,
                adoption_commit_sha=HEAD,
            )
        )
        self.assertNotEqual(dirty.get("closeout_state"), "candidate_adopted")
        self.assertIn("valuable_dirty_state", dirty["reason_codes"])

    def test_candidate_adoption_closeout_binding_must_be_complete(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires candidate_id"):
            closeout.classify(
                self.observation(
                    candidate_id="d" * 64,
                    adoption_receipt_sha256="e" * 64,
                )
            )

    def test_candidate_adoption_hash_bindings_are_strict(self) -> None:
        with self.assertRaisesRegex(ValueError, "candidate_id"):
            closeout.classify(
                self.observation(
                    candidate_id="not-a-sha",
                    adoption_receipt_sha256="e" * 64,
                    adoption_commit_sha=HEAD,
                )
            )

    def test_no_change_proof_is_terminal(self) -> None:
        result = closeout.classify(
            self.observation(
                head_sha=BASE,
                remote_head_sha=BASE,
                no_change_proven=True,
            )
        )
        self.assertEqual(result["closeout_state"], "no_change_proven")

    def test_deployment_requires_exact_head_binding(self) -> None:
        success = closeout.classify(
            self.observation(
                pr_state="merged",
                pr_number=631,
                pr_head_sha=HEAD,
                merged_sha=MERGED,
                deployed_sha=MERGED,
            )
        )
        self.assertEqual(success["closeout_state"], "deployed")
        self.assertTrue(success["lease_release_ready"])

        mismatch = closeout.classify(
            self.observation(
                deployed_sha="d" * 40,
                pr_state=None,
            )
        )
        self.assertEqual(mismatch["phase"], "rescue_required")
        self.assertIn("deployed_head_mismatch", mismatch["reason_codes"])

    def test_deployed_requires_clean_worktree_and_zero_ahead(self) -> None:
        dirty = closeout.classify(
            self.observation(
                deployed_sha=HEAD,
                git_dirty=True,
            )
        )
        self.assertEqual(dirty["phase"], "rescue_required")
        self.assertIsNone(dirty["closeout_state"])
        self.assertIn("valuable_dirty_state", dirty["reason_codes"])
        self.assertFalse(dirty["lease_release_ready"])

        ahead = closeout.classify(
            self.observation(
                deployed_sha=HEAD,
                ahead_commits=1,
            )
        )
        self.assertEqual(ahead["phase"], "rescue_required")
        self.assertIsNone(ahead["closeout_state"])
        self.assertIn("unpushed_commits", ahead["reason_codes"])
        self.assertFalse(ahead["lease_release_ready"])

        unobserved_ahead = closeout.classify(
            self.observation(
                deployed_sha=HEAD,
                ahead_commits=None,
            )
        )
        self.assertEqual(unobserved_ahead["phase"], "rescue_required")
        self.assertIsNone(unobserved_ahead["closeout_state"])
        self.assertIn("ahead_count_unobserved", unobserved_ahead["reason_codes"])
        self.assertFalse(unobserved_ahead["lease_release_ready"])

    def test_no_change_proven_rejects_truthy_non_booleans(self) -> None:
        for value in ("yes", 1, "true", object()):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "no_change_proven"):
                    closeout.classify(self.observation(no_change_proven=value))

        refused = closeout.classify(
            self.observation(
                head_sha=BASE,
                remote_head_sha=BASE,
                no_change_proven=False,
            )
        )
        self.assertNotEqual(refused.get("closeout_state"), "no_change_proven")

    def test_readback_error_can_close_only_with_durable_followup(self) -> None:
        blocked = closeout.classify(
            self.observation(
                writer_state="outcome_unknown",
                durable_followup_id="followup-1",
                readback_errors=("github-timeout",),
            )
        )
        self.assertEqual(
            blocked["closeout_state"], "blocked_with_durable_followup"
        )
        self.assertFalse(blocked["lease_release_ready"])

        rescue = closeout.classify(
            self.observation(
                writer_state="outcome_unknown",
                readback_errors=("github-timeout",),
            )
        )
        self.assertEqual(rescue["phase"], "rescue_required")
        self.assertIn("create_durable_followup", rescue["recovery_actions"])

    def test_active_liveness_with_readback_errors_stays_non_terminal(self) -> None:
        active = closeout.classify(
            self.observation(
                writer_state="running",
                task_active=True,
                durable_followup_id="followup-1",
                readback_errors=("github-timeout",),
            )
        )
        self.assertEqual(active["phase"], "active")
        self.assertIsNone(active["closeout_state"])
        self.assertFalse(active["lease_release_ready"])
        self.assertEqual(active["reason_codes"], ["writer_or_process_active"])

        process_active = closeout.classify(
            self.observation(
                writer_state="completed",
                process_active=True,
                durable_followup_id="followup-1",
                readback_errors=("github-timeout",),
            )
        )
        self.assertEqual(process_active["phase"], "active")
        self.assertIsNone(process_active["closeout_state"])

    def test_unknown_liveness_with_readback_errors_stays_rescue(self) -> None:
        rescue = closeout.classify(
            self.observation(
                writer_state="completed",
                process_active=None,
                durable_followup_id="followup-1",
                readback_errors=("github-timeout",),
            )
        )
        self.assertEqual(rescue["phase"], "rescue_required")
        self.assertIsNone(rescue["closeout_state"])
        self.assertFalse(rescue["lease_release_ready"])
        self.assertIn("readback_error:github-timeout", rescue["reason_codes"])
        self.assertIn(
            "observation_unknown:process_active", rescue["reason_codes"]
        )
        self.assertIn("create_durable_followup", rescue["recovery_actions"])

    def test_pr_merged_requires_head_binding_clean_zero_ahead(self) -> None:
        by_merged = closeout.classify(
            self.observation(
                head_sha=MERGED,
                remote_head_sha=MERGED,
                pr_state="merged",
                pr_number=633,
                pr_head_sha=HEAD,
                merged_sha=MERGED,
            )
        )
        self.assertEqual(by_merged["closeout_state"], "pr_merged")
        self.assertTrue(by_merged["lease_release_ready"])

        by_pr_head = closeout.classify(
            self.observation(
                pr_state="merged",
                pr_number=633,
                pr_head_sha=HEAD,
                merged_sha=MERGED,
            )
        )
        self.assertEqual(by_pr_head["closeout_state"], "pr_merged")
        self.assertTrue(by_pr_head["lease_release_ready"])

        unbound = closeout.classify(
            self.observation(
                head_sha=None,
                pr_state="merged",
                pr_number=633,
                pr_head_sha=HEAD,
                merged_sha=MERGED,
            )
        )
        self.assertEqual(unbound["phase"], "rescue_required")
        self.assertIn("merged_head_unbound", unbound["reason_codes"])
        self.assertFalse(unbound["lease_release_ready"])

        mismatch = closeout.classify(
            self.observation(
                head_sha="d" * 40,
                remote_head_sha="d" * 40,
                pr_state="merged",
                pr_number=633,
                pr_head_sha=HEAD,
                merged_sha=MERGED,
            )
        )
        self.assertEqual(mismatch["phase"], "rescue_required")
        self.assertIn("merged_head_mismatch", mismatch["reason_codes"])
        self.assertFalse(mismatch["lease_release_ready"])

        dirty = closeout.classify(
            self.observation(
                pr_state="merged",
                pr_number=633,
                pr_head_sha=HEAD,
                merged_sha=HEAD,
                git_dirty=True,
            )
        )
        self.assertEqual(dirty["phase"], "rescue_required")
        self.assertIn("valuable_dirty_state", dirty["reason_codes"])
        self.assertFalse(dirty["lease_release_ready"])

        ahead = closeout.classify(
            self.observation(
                pr_state="merged",
                pr_number=633,
                pr_head_sha=HEAD,
                merged_sha=HEAD,
                ahead_commits=1,
            )
        )
        self.assertEqual(ahead["phase"], "rescue_required")
        self.assertIn("unpushed_commits", ahead["reason_codes"])
        self.assertFalse(ahead["lease_release_ready"])

    def test_assessment_is_audit_bound_without_granting_cleanup(self) -> None:
        records = []
        result = closeout.assess(
            self.observation(
                pr_number=631,
                pr_state="open",
                pr_head_sha=HEAD,
            ),
            observed_at_unix=200,
            append_audit=lambda record: records.append(record) or "e" * 64,
        )
        self.assertEqual(result["audit_record_sha256"], "e" * 64)
        self.assertRegex(result["assessment_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("workspace_cleanup_authority", result["does_not_establish"])
        self.assertEqual(records[0]["operation"], "lane-closeout-assessment")

    def test_terminal_assessment_validator_rejects_tampering(self) -> None:
        assessment = closeout.assess(
            self.observation(pr_number=631, pr_state="open", pr_head_sha=HEAD),
            observed_at_unix=200,
        )
        self.assertEqual(closeout.validate_terminal_assessment(assessment), assessment)
        assessment["reason_codes"] = ["tampered"]
        with self.assertRaisesRegex(closeout.LaneCloseoutError, "digest mismatch"):
            closeout.validate_terminal_assessment(assessment)

    def test_unknown_live_observation_fails_to_rescue(self) -> None:
        result = closeout.classify(self.observation(process_active=None))
        self.assertEqual(result["phase"], "rescue_required")
        self.assertIn(
            "observation_unknown:process_active", result["reason_codes"]
        )


if __name__ == "__main__":
    unittest.main()

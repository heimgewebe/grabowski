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

        mismatch = closeout.classify(
            self.observation(
                deployed_sha="d" * 40,
                pr_state=None,
            )
        )
        self.assertEqual(mismatch["phase"], "rescue_required")
        self.assertIn("deployed_head_mismatch", mismatch["reason_codes"])

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

    def test_unknown_live_observation_fails_to_rescue(self) -> None:
        result = closeout.classify(self.observation(process_active=None))
        self.assertEqual(result["phase"], "rescue_required")
        self.assertIn(
            "observation_unknown:process_active", result["reason_codes"]
        )


if __name__ == "__main__":
    unittest.main()

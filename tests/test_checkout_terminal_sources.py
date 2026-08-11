from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_checkouts as checkouts
import grabowski_checkout_terminal_sources as sources
import grabowski_lane_closeout as lane_closeout
import grabowski_work_acquire as work_acquire


class CheckoutTerminalSourcesTests(unittest.TestCase):
    def test_work_lane_is_a_first_class_terminal_evidence_source(self) -> None:
        self.assertIn("work_lane", checkouts.TERMINAL_EVIDENCE_SOURCE_KINDS)
        self.assertIs(sources._OBSERVERS["work_lane"], sources.work_lane_terminal_evidence)

    def test_work_lane_without_terminal_closeout_fails_closed(self) -> None:
        lane_id = "a" * 32
        record = {
            "lane_id": lane_id,
            "state": "ready",
            "receipt_sha256": "b" * 64,
        }
        with patch.object(work_acquire, "_read_state", return_value=record):
            with self.assertRaisesRegex(RuntimeError, "no terminal closeout evidence"):
                sources.work_lane_terminal_evidence(lane_id)

    def test_work_lane_terminal_evidence_is_lane_and_audit_bound(self) -> None:
        lane_id = "c" * 32
        assessment = lane_closeout.assess(
            lane_closeout.LaneCloseoutObservation(
                lane_id=lane_id,
                repository="/tmp/repo",
                workspace="/tmp/worktree",
                branch="feat/example",
                base_revision="a" * 40,
                writer_state="completed",
                task_active=False,
                process_active=False,
                lease_active=True,
                git_dirty=False,
                head_sha="b" * 40,
                remote_head_sha="b" * 40,
                ahead_commits=0,
                behind_commits=0,
                pr_number=1,
                pr_state="merged",
                pr_head_sha="b" * 40,
                merged_sha="b" * 40,
            ),
            observed_at_unix=200,
        )
        record = {
            "lane_id": lane_id,
            "state": "ready",
            "receipt_sha256": "d" * 64,
            "terminal_closeout": {
                "schema_version": 1,
                "kind": "grabowski.work_lane_terminal_closeout",
                "closeout_state": assessment["closeout_state"],
                "assessment_sha256": assessment["assessment_sha256"],
                "expected_receipt_sha256": "e" * 64,
                "assessment": assessment,
            },
        }
        with (
            patch.object(work_acquire, "_read_state", return_value=record),
            patch.object(
                work_acquire,
                "_find_terminal_closeout_audit",
                return_value="f" * 64,
            ),
        ):
            evidence = sources.work_lane_terminal_evidence(lane_id)
        self.assertEqual(evidence["kind"], "work_lane")
        self.assertEqual(evidence["source_id"], lane_id)
        self.assertEqual(evidence["terminal_state"], "pr_merged")
        self.assertEqual(evidence["lane_receipt_sha256"], "d" * 64)
        self.assertEqual(
            evidence["terminal_closeout_audit_record_sha256"],
            "f" * 64,
        )
        self.assertEqual(
            evidence["evidence_sha256"],
            checkouts._sha256_json(
                {key: value for key, value in evidence.items() if key != "evidence_sha256"}
            ),
        )

    def test_invalid_lane_identity_is_rejected_before_observation(self) -> None:
        with self.assertRaisesRegex(ValueError, "32-character lowercase hex lane id"):
            sources.work_lane_terminal_evidence("chat-thread-identity")


if __name__ == "__main__":
    unittest.main()

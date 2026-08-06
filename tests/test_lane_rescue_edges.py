from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_lane_closeout as closeout
import grabowski_lane_rescue as rescue


OWNER = "operator:controller:edges"
BASE = "a" * 40
HEAD = "b" * 40


def _plan() -> dict:
    observation = closeout.LaneCloseoutObservation(
        lane_id="lane-edges",
        repository="/tmp/repo",
        workspace="/tmp/workspace",
        branch="feat/edges",
        base_revision=BASE,
        writer_state="failed",
        task_active=False,
        process_active=False,
        lease_active=True,
        git_dirty=True,
        head_sha=HEAD,
        remote_head_sha=HEAD,
        ahead_commits=0,
        behind_commits=0,
    )
    return rescue.build_plan(
        observation,
        lane_owner_id=OWNER,
        requesting_owner_id=OWNER,
        resource_keys=["path:/tmp/workspace"],
    )


class LaneRescueEdgeTests(unittest.TestCase):
    def test_explicit_not_applied_allows_safe_retry(self) -> None:
        plan = _plan()

        def commit(payload: dict) -> dict:
            raise rescue.EffectNotApplied(payload["action"], "validation failed before write")

        receipt = rescue.execute_plan(
            plan,
            actor_owner_id=OWNER,
            adapters={
                "commit": commit,
                "create_pr": lambda payload: {"receipt_sha256": "c" * 64},
            },
        )
        self.assertEqual(receipt["status"], "blocked_before_effect")
        self.assertTrue(receipt["retry_authorized"])
        self.assertFalse(receipt["readback_required"])

    def test_unspecific_exception_is_outcome_unknown_even_first(self) -> None:
        plan = _plan()

        def commit(payload: dict) -> dict:
            raise RuntimeError("connection vanished")

        receipt = rescue.execute_plan(
            plan,
            actor_owner_id=OWNER,
            adapters={
                "commit": commit,
                "create_pr": lambda payload: {"receipt_sha256": "d" * 64},
            },
        )
        self.assertEqual(receipt["status"], "outcome_unknown")
        self.assertFalse(receipt["retry_authorized"])
        self.assertTrue(receipt["readback_required"])

    def test_non_mapping_adapter_result_is_outcome_unknown(self) -> None:
        plan = _plan()
        receipt = rescue.execute_plan(
            plan,
            actor_owner_id=OWNER,
            adapters={
                "commit": lambda payload: None,  # type: ignore[return-value]
                "create_pr": lambda payload: {"receipt_sha256": "e" * 64},
            },
        )
        self.assertEqual(receipt["status"], "outcome_unknown")
        self.assertEqual(receipt["error_class"], "INVALID_ADAPTER_RESULT")
        self.assertFalse(receipt["retry_authorized"])

    def test_finalize_rejects_tampered_execution_receipt(self) -> None:
        plan = _plan()
        receipt = rescue.execute_plan(
            plan,
            actor_owner_id=OWNER,
            adapters={
                "commit": lambda payload: {"receipt_sha256": "f" * 64},
                "create_pr": lambda payload: {"receipt_sha256": "1" * 64},
            },
        )
        tampered = dict(receipt)
        tampered["status"] = "terminal"
        terminal_observation = closeout.LaneCloseoutObservation(
            lane_id="lane-edges",
            repository="/tmp/repo",
            workspace="/tmp/workspace",
            branch="feat/edges",
            base_revision=BASE,
            writer_state="completed",
            task_active=False,
            process_active=False,
            lease_active=True,
            git_dirty=False,
            head_sha=BASE,
            remote_head_sha=BASE,
            ahead_commits=0,
            behind_commits=0,
            no_change_proven=True,
        )
        with self.assertRaisesRegex(rescue.LaneRescueInputError, "integrity"):
            rescue.finalize(
                terminal_observation,
                tampered,
                lane_owner_id=OWNER,
                requesting_owner_id=OWNER,
            )


if __name__ == "__main__":
    unittest.main()

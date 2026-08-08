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


BASE = "a" * 40
HEAD = "b" * 40
OWNER = "operator:controller:test"
RESOURCES = ["path:/tmp/lane", "repo:/tmp/repo:branch:feat/test"]


def observation(**overrides: object) -> closeout.LaneCloseoutObservation:
    values: dict[str, object] = {
        "lane_id": "lane-test",
        "repository": "/tmp/repo",
        "workspace": "/tmp/lane",
        "branch": "feat/test",
        "base_revision": BASE,
        "writer_state": "failed",
        "task_active": False,
        "process_active": False,
        "lease_active": True,
        "git_dirty": False,
        "head_sha": HEAD,
        "remote_head_sha": HEAD,
        "ahead_commits": 0,
        "behind_commits": 0,
        "pr_number": None,
        "pr_state": None,
        "pr_head_sha": None,
        "pr_origin": None,
        "merged_sha": None,
        "deployed_sha": None,
        "no_change_proven": False,
        "durable_followup_id": None,
        "readback_errors": (),
    }
    values.update(overrides)
    return closeout.LaneCloseoutObservation(**values)  # type: ignore[arg-type]


def plan(obs: closeout.LaneCloseoutObservation, **kwargs: object) -> dict:
    return rescue.build_plan(
        obs,
        lane_owner_id=OWNER,
        requesting_owner_id=OWNER,
        resource_keys=RESOURCES,
        **kwargs,  # type: ignore[arg-type]
    )


class LaneRescueTests(unittest.TestCase):
    def test_active_writer_is_observed_without_effects(self) -> None:
        value = plan(observation(writer_state="running", task_active=True))
        self.assertEqual(value["mode"], "observe")
        self.assertEqual(value["actions"], [])
        receipt = rescue.execute_plan(value, actor_owner_id=OWNER, adapters={})
        self.assertEqual(receipt["status"], "observe")
        self.assertEqual(receipt["effects"], [])
        self.assertFalse(receipt["lease_release_ready"])

    def test_unknown_liveness_requires_readback_without_effects(self) -> None:
        value = plan(observation(task_active=None))
        self.assertEqual(value["mode"], "readback_required")
        receipt = rescue.execute_plan(value, actor_owner_id=OWNER, adapters={})
        self.assertEqual(receipt["status"], "readback_required")
        self.assertTrue(receipt["readback_required"])
        self.assertFalse(receipt["retry_authorized"])

    def test_dirty_unpushed_missing_pr_has_deterministic_actions(self) -> None:
        value = plan(
            observation(
                git_dirty=True,
                ahead_commits=2,
                remote_head_sha=BASE,
            )
        )
        self.assertEqual(value["mode"], "execute")
        self.assertEqual(value["actions"], ["commit", "push", "create_pr"])
        self.assertEqual(value["handoff"]["next_role"], "scoped_writer")

    def test_open_pr_head_mismatch_plans_update(self) -> None:
        value = plan(
            observation(
                pr_number=12,
                pr_state="open",
                pr_head_sha=BASE,
                pr_origin="opened",
            )
        )
        self.assertEqual(value["actions"], ["update_pr"])

    def test_no_change_is_terminal_and_release_ready(self) -> None:
        value = plan(
            observation(
                head_sha=BASE,
                remote_head_sha=BASE,
                no_change_proven=True,
            )
        )
        self.assertEqual(value["mode"], "terminal")
        receipt = rescue.execute_plan(value, actor_owner_id=OWNER, adapters={})
        self.assertEqual(receipt["closeout_state"], "no_change_proven")
        self.assertTrue(receipt["lease_release_ready"])

    def test_merged_and_deployed_are_terminal(self) -> None:
        merged = plan(
            observation(
                writer_state="completed",
                pr_number=12,
                pr_state="merged",
                pr_head_sha=HEAD,
                merged_sha=HEAD,
            )
        )
        deployed = plan(
            observation(
                writer_state="completed",
                merged_sha=HEAD,
                deployed_sha=HEAD,
            )
        )
        self.assertEqual(merged["assessment"]["closeout_state"], "pr_merged")
        self.assertEqual(deployed["assessment"]["closeout_state"], "deployed")

    def test_durable_blocker_is_terminal_but_not_release_ready(self) -> None:
        value = plan(observation(durable_followup_id="followup-1"))
        receipt = rescue.execute_plan(value, actor_owner_id=OWNER, adapters={})
        self.assertEqual(receipt["closeout_state"], "blocked_with_durable_followup")
        self.assertFalse(receipt["lease_release_ready"])

    def test_missing_adapter_blocks_before_any_effect(self) -> None:
        value = plan(observation(git_dirty=True))
        receipt = rescue.execute_plan(value, actor_owner_id=OWNER, adapters={})
        self.assertEqual(receipt["status"], "blocked_before_effect")
        self.assertEqual(receipt["effects"], [])
        self.assertTrue(receipt["retry_authorized"])

    def test_effect_response_loss_is_outcome_unknown_and_replay_safe(self) -> None:
        calls: list[str] = []

        def uncertain(payload: dict) -> dict:
            calls.append(payload["action"])
            raise rescue.EffectOutcomeUnknown(payload["action"], "response lost")

        value = plan(observation(git_dirty=True))
        adapters = {
            "commit": uncertain,
            "create_pr": lambda payload: {"receipt_sha256": "c" * 64},
        }
        first = rescue.execute_plan(value, actor_owner_id=OWNER, adapters=adapters)
        self.assertEqual(first["status"], "outcome_unknown")
        self.assertFalse(first["retry_authorized"])
        second = rescue.execute_plan(
            value,
            actor_owner_id=OWNER,
            adapters=adapters,
            prior_receipt=first,
        )
        self.assertTrue(second["replayed"])
        self.assertEqual(calls, ["commit"])

    def test_failure_after_effect_is_outcome_unknown(self) -> None:
        value = plan(observation(git_dirty=True, ahead_commits=1, remote_head_sha=BASE))

        def commit(payload: dict) -> dict:
            return {"receipt_sha256": "d" * 64}

        def push(payload: dict) -> dict:
            raise RuntimeError("transport failed")

        receipt = rescue.execute_plan(
            value,
            actor_owner_id=OWNER,
            adapters={
                "commit": commit,
                "push": push,
                "create_pr": lambda payload: {"receipt_sha256": "e" * 64},
            },
        )
        self.assertEqual(receipt["status"], "outcome_unknown")
        self.assertEqual([item["action"] for item in receipt["effects"]], ["commit"])
        self.assertTrue(receipt["readback_required"])
        self.assertFalse(receipt["retry_authorized"])

    def test_effects_require_fresh_terminal_readback(self) -> None:
        value = plan(observation(git_dirty=True))
        receipt = rescue.execute_plan(
            value,
            actor_owner_id=OWNER,
            adapters={
                "commit": lambda payload: {"receipt_sha256": "1" * 64},
                "create_pr": lambda payload: {"receipt_sha256": "2" * 64},
            },
        )
        self.assertEqual(receipt["status"], "effects_applied")
        self.assertFalse(receipt["lease_release_ready"])
        final = rescue.finalize(
            observation(
                writer_state="completed",
                pr_number=42,
                pr_state="open",
                pr_head_sha=HEAD,
                pr_origin="opened",
            ),
            receipt,
            lane_owner_id=OWNER,
            requesting_owner_id=OWNER,
        )
        self.assertEqual(final["closeout_state"], "pr_opened")
        self.assertTrue(final["lease_release_ready"])

    def test_recovery_consumes_persisted_terminal_lane_truth(self) -> None:
        lane_id = "f" * 32
        terminal = closeout.assess(
            observation(lane_id=lane_id, head_sha=BASE, remote_head_sha=BASE, no_change_proven=True),
            observed_at_unix=200,
        )
        receipt = {
            "lane_id": lane_id,
            "inputs": {
                "repo": "/tmp/repo",
                "target_path": "/tmp/lane",
                "branch": "feat/test",
                "base_head": BASE,
            },
            "terminal_closeout": {
                "schema_version": 1, "kind": "grabowski.work_lane_terminal_closeout",
                "closeout_state": terminal["closeout_state"],
                "assessment_sha256": terminal["assessment_sha256"], "assessment": terminal,
            },
        }
        plan = rescue.build_plan(
            observation(lane_id=lane_id, git_dirty=True, ahead_commits=2, remote_head_sha=BASE),
            lane_owner_id=OWNER, requesting_owner_id=OWNER, resource_keys=RESOURCES,
            lane_receipt_reader=lambda _: receipt,
        )
        self.assertEqual(plan["mode"], "terminal")
        self.assertEqual(plan["assessment_sha256"], terminal["assessment_sha256"])
        self.assertEqual(plan["actions"], [])

    def test_recovery_rejects_persisted_terminal_truth_from_other_identity(self) -> None:
        lane_id = "f" * 32
        terminal = closeout.assess(
            observation(
                lane_id=lane_id,
                head_sha=BASE,
                remote_head_sha=BASE,
                no_change_proven=True,
            ),
            observed_at_unix=200,
        )
        receipt = {
            "lane_id": lane_id,
            "inputs": {
                "repo": "/tmp/repo",
                "target_path": "/tmp/lane",
                "branch": "feat/test",
                "base_head": BASE,
            },
            "terminal_closeout": {
                "schema_version": 1,
                "kind": "grabowski.work_lane_terminal_closeout",
                "closeout_state": terminal["closeout_state"],
                "assessment_sha256": terminal["assessment_sha256"],
                "assessment": terminal,
            },
        }
        mismatches = {
            "repository": "/tmp/other-repo",
            "workspace": "/tmp/other-lane",
            "branch": "feat/other",
            "base_revision": "c" * 40,
        }
        for field, value in mismatches.items():
            with self.subTest(field=field), self.assertRaisesRegex(
                rescue.LaneRescueInputError,
                "persisted lane receipt identity does not match observation",
            ):
                rescue.build_plan(
                    observation(lane_id=lane_id, **{field: value}),
                    lane_owner_id=OWNER,
                    requesting_owner_id=OWNER,
                    resource_keys=RESOURCES,
                    lane_receipt_reader=lambda _: receipt,
                )

    def test_owner_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(rescue.LaneRescueInputError, "does not match"):
            rescue.build_plan(
                observation(),
                lane_owner_id=OWNER,
                requesting_owner_id="operator:other",
                resource_keys=RESOURCES,
            )
        value = plan(observation())
        with self.assertRaisesRegex(rescue.LaneRescueInputError, "does not match"):
            rescue.execute_plan(value, actor_owner_id="operator:other", adapters={})

    def test_merge_and_deployment_need_controller_authority(self) -> None:
        with self.assertRaisesRegex(rescue.LaneRescueInputError, "authorization"):
            plan(observation(), requested_actions=["merge"])
        value = plan(
            observation(),
            requested_actions=["merge", "deployment"],
            controller_authorized_actions=["merge", "deployment"],
        )
        self.assertIn("merge", value["actions"])
        self.assertIn("deployment", value["actions"])

    def test_plan_and_receipts_are_digest_bound(self) -> None:
        value = plan(observation())
        self.assertEqual(len(value["plan_sha256"]), 64)
        receipt = rescue.execute_plan(
            value,
            actor_owner_id=OWNER,
            adapters={"create_pr": lambda payload: {"receipt_sha256": "f" * 64}},
        )
        self.assertEqual(len(receipt["receipt_sha256"]), 64)
        tampered = dict(value)
        tampered["branch"] = "feat/other"
        with self.assertRaisesRegex(rescue.LaneRescueInputError, "integrity"):
            rescue.execute_plan(tampered, actor_owner_id=OWNER, adapters={})


if __name__ == "__main__":
    unittest.main()

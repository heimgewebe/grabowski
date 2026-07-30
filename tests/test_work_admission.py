from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import grabowski_work_admission as admission


class WorkAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _main(self, *, dirty: bool = False) -> dict[str, object]:
        return {
            "path": str(self.repo),
            "is_main": True,
            "branch": "main",
            "status": {"dirty": dirty},
            "coordination": {
                "resource_leases": [],
                "tasks": [],
                "processes": [],
            },
            "lifecycle": {},
            "lifecycle_state": "main",
        }

    def _linked(
        self,
        *,
        state: str,
        dirty: bool = False,
        owner: str | None = None,
        source_id: str | None = None,
        foreign_lease: bool = False,
    ) -> dict[str, object]:
        lifecycle: dict[str, object] = {}
        if owner is not None or source_id is not None:
            lifecycle["binding"] = {
                "owner_id": owner,
                "source_kind": "bureau_task",
                "source_id": source_id,
            }
        return {
            "path": str(self.repo.parent / "worktrees" / state),
            "is_main": False,
            "branch": f"feat/{state}",
            "status": {"dirty": dirty},
            "coordination": {
                "resource_leases": (
                    [
                        {
                            "blocking": True,
                            "resource_key": "path:/foreign",
                            "owner_id": "foreign-owner",
                        }
                    ]
                    if foreign_lease
                    else []
                ),
                "tasks": [],
                "processes": [],
            },
            "lifecycle": lifecycle,
            "lifecycle_state": state,
        }

    @staticmethod
    def _reconciliation(
        *, blocking: bool = False, truncated: bool = False
    ) -> dict[str, object]:
        return {
            "bindings": (
                [
                    {
                        "blocking": True,
                        "checkout_key": "abc",
                        "state": "orphaned",
                        "reasons": ["bound checkout missing"],
                    }
                ]
                if blocking
                else []
            ),
            "pagination": {"has_more": truncated},
            "source_snapshot": {"repository_errors": []},
            "snapshot_sha256": "b" * 64,
        }

    def _assess(
        self,
        worktrees: list[dict[str, object]],
        *,
        reconciliation: dict[str, object] | None = None,
        **kwargs: object,
    ) -> dict[str, object]:
        return admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="worktree_create",
            inventory_loader=lambda _repo: {
                "worktrees": worktrees,
                "inventory_sha256": "a" * 64,
            },
            reconciliation_loader=lambda _repo: (
                reconciliation or self._reconciliation()
            ),
            **kwargs,
        )

    def test_clean_primary_only_allows_new_broad_lane(self) -> None:
        result = self._assess([self._main()])
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["blockers"], [])
        self.assertTrue(result["read_only"])
        self.assertEqual(len(result["assessment_sha256"]), 64)

    def test_dirty_or_foreign_live_work_blocks_fail_closed(self) -> None:
        dirty = self._assess(
            [self._main(), self._linked(state="retained", dirty=True, owner="owner-a")]
        )
        foreign = self._assess(
            [
                self._main(),
                self._linked(
                    state="retained",
                    owner="foreign-owner",
                    foreign_lease=True,
                ),
            ]
        )
        self.assertEqual(dirty["decision"], "blocked")
        self.assertIn("dirty-worktree", dirty["blocker_codes"])
        self.assertEqual(foreign["decision"], "blocked")
        self.assertIn("foreign-live-coordination", foreign["blocker_codes"])
        self.assertIn("foreign-retained-worktree", foreign["blocker_codes"])

    def test_clean_terminal_or_orphaned_state_requires_convergence_first(self) -> None:
        terminal = self._assess(
            [self._main(), self._linked(state="cleanup_candidate")]
        )
        orphaned = self._assess(
            [self._main()], reconciliation=self._reconciliation(blocking=True)
        )
        self.assertEqual(terminal["decision"], "converge_first")
        self.assertIn("worktree-convergence-required", terminal["blocker_codes"])
        self.assertEqual(orphaned["decision"], "converge_first")
        self.assertIn("binding-reconciliation-blocking", orphaned["blocker_codes"])

    def test_convergence_mode_allows_only_clean_convergence_work(self) -> None:
        inventory = lambda _repo: {
            "worktrees": [self._main(), self._linked(state="cleanup_candidate")],
            "inventory_sha256": "a" * 64,
        }
        reconciliation = lambda _repo: self._reconciliation()
        with self.assertRaises(admission.WorkAdmissionBlocked):
            admission.require_repository_admission(
                mode="normal",
                repo=str(self.repo),
                owner_id="owner-a",
                operation="broad_repository_lease",
                inventory_loader=inventory,
                reconciliation_loader=reconciliation,
            )
        result = admission.require_repository_admission(
            mode="convergence",
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=inventory,
            reconciliation_loader=reconciliation,
        )
        self.assertEqual(result["decision"], "converge_first")

    def test_equivalent_source_binding_blocks_duplicate_lane(self) -> None:
        result = self._assess(
            [
                self._main(),
                self._linked(
                    state="retained",
                    owner="owner-a",
                    source_id="GRABOWSKI-T083",
                ),
            ],
            source_kind="bureau_task",
            source_id="GRABOWSKI-T083",
            target_path=str(self.repo.parent / "new-target"),
        )
        self.assertEqual(result["decision"], "converge_first")
        self.assertIn("similar-active-source-binding", result["blocker_codes"])

    def test_same_owner_task_and_current_process_do_not_self_block(self) -> None:
        linked = self._linked(state="retained", owner="owner-a")
        linked["coordination"] = {
            "resource_leases": [],
            "tasks": [
                {
                    "task_id": "task-a",
                    "lease_owner_id": "owner-a",
                }
            ],
            "processes": [{"pid": admission.os.getpid()}],
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "allow")
        self.assertNotIn("foreign-live-coordination", result["blocker_codes"])

    def test_unattributed_other_process_still_blocks(self) -> None:
        linked = self._linked(state="retained", owner="owner-a")
        linked["coordination"] = {
            "resource_leases": [],
            "tasks": [],
            "processes": [{"pid": admission.os.getpid() + 100_000}],
        }
        result = self._assess([self._main(), linked])
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("foreign-live-coordination", result["blocker_codes"])

    def test_loader_failure_becomes_typed_unobservable_block(self) -> None:
        result = admission.assess_repository_admission(
            repo=str(self.repo),
            owner_id="owner-a",
            operation="broad_repository_lease",
            inventory_loader=lambda _repo: (_ for _ in ()).throw(
                RuntimeError("inventory unavailable")
            ),
            reconciliation_loader=lambda _repo: self._reconciliation(),
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("inventory-unobservable", result["blocker_codes"])
        self.assertTrue(
            any(
                "inventory unavailable" in str(item.get("detail", ""))
                for item in result["blockers"]
            )
        )

    def test_truncated_reconciliation_is_unobservable_and_blocks(self) -> None:
        result = self._assess(
            [self._main()], reconciliation=self._reconciliation(truncated=True)
        )
        self.assertEqual(result["decision"], "blocked")
        self.assertIn("reconciliation-unobservable", result["blocker_codes"])


if __name__ == "__main__":
    unittest.main()

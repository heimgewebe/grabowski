from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_current_work as current_work


REPOSITORY = "/home/alex/repos/grabowski"


def task(
    task_id: str,
    state: str = "running",
    *,
    cwd: str = "/home/alex/repos/grabowski",
    updated: int = 20,
    action_required: bool = False,
    action_reason: str = "",
) -> dict:
    return {
        "task_id": task_id,
        "state": state,
        "host": "heim-pc",
        "unit": f"grabowski-task-{task_id}.service",
        "cwd": cwd,
        "lease_owner_id": f"task:{task_id}",
        "resource_keys": [],
        "created_at_unix": 10,
        "updated_at_unix": updated,
        "recommended_next_action": "inspect",
        "action_required": action_required,
        "action_reason": action_reason,
    }


def lease(owner_id: str, resource_key: str, *, updated: int = 30) -> dict:
    return {
        "resource_key": resource_key,
        "owner_id": owner_id,
        "purpose": "test",
        "acquired_at_unix": 10,
        "updated_at_unix": updated,
        "expires_at_unix": 1000,
    }


def checkout(
    key: str,
    path: str,
    *,
    dirty: bool = False,
    task_ids: list[str] | None = None,
    owner_ids: list[str] | None = None,
    processes: list[dict] | None = None,
    blocking: bool = False,
    is_main: bool = False,
    cleanup_candidate: bool = False,
    lifecycle_state: str = "active",
) -> dict:
    return {
        "checkout_key": key,
        "path": path,
        "head": "a" * 40,
        "branch": "feat/test",
        "is_main": is_main,
        "status": {"dirty": dirty, "entry_count": 1 if dirty else 0},
        "coordination": {
            "blocking": blocking,
            "tasks": [{"task_id": item} for item in task_ids or []],
            "resource_leases": [
                {"owner_id": item} for item in owner_ids or []
            ],
            "processes": processes or [],
        },
        "lifecycle": {"state": lifecycle_state},
        "lifecycle_state": lifecycle_state,
        "cleanup_candidate": cleanup_candidate,
    }


def worker(
    worker_id: str,
    *,
    state: str = "running",
    action_required: bool = False,
    reason: str = "",
) -> dict:
    return {
        "worker_id": worker_id,
        "state": state,
        "unit": f"grabowski-worker-{worker_id}.service",
        "created_at_unix": 10,
        "updated_at_unix": 40,
        "projection": {
            "fresh": True,
            "action_required": action_required,
            "reason": reason,
        },
    }


def project(**overrides: object) -> dict:
    payload = {
        "tasks_payload": {"tasks": [], "pagination": {"has_more": False}},
        "resources_payload": {"leases": [], "count": 0, "truncated": False},
        "checkout_payloads": [{"repository": REPOSITORY, "worktrees": []}],
        "repository_filters": [REPOSITORY],
        "tmux_payload": {"returncode": 0, "stdout": ""},
        "process_payload": {"returncode": 0, "lines": []},
        "browser_payload": {"workers": [], "has_more": False},
        "gui_payload": {"workers": [], "has_more": False},
        "generated_at_unix": 100,
        "limit": 20,
    }
    payload.update(overrides)
    return current_work.build_current_work_projection(**payload)


class CurrentWorkProjectionTests(unittest.TestCase):
    def test_task_lease_and_checkout_form_one_authority_bound_group(self) -> None:
        task_id = "abc123"
        result = project(
            tasks_payload={"tasks": [task(task_id)], "pagination": {"has_more": False}},
            resources_payload={
                "leases": [lease(f"task:{task_id}", "path:/tmp/work")],
                "count": 1,
                "truncated": False,
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "checkout-a",
                            "/home/alex/repos/grabowski",
                            task_ids=[task_id],
                            blocking=True,
                        )
                    ],
                }
            ],
        )
        self.assertEqual(result["count"], 1)
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"task:{task_id}")
        self.assertEqual(group["projection_state"], "active")
        self.assertEqual(group["binding_status"], "authority-bound")
        self.assertEqual(len(group["authority_refs"]), 1)
        self.assertEqual(len(group["lease_refs"]), 1)
        self.assertEqual(len(group["checkout_refs"]), 1)

    def test_terminal_task_with_live_lease_is_attention(self) -> None:
        task_id = "done123"
        result = project(
            tasks_payload={
                "tasks": [task(task_id, "completed")],
                "pagination": {"has_more": False},
            },
            resources_payload={
                "leases": [lease(f"task:{task_id}", "repo:/tmp/repo")],
                "count": 1,
                "truncated": False,
            },
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn("terminal-task-with-live-surfaces", group["action_reasons"])

    def test_completed_task_without_current_surface_is_omitted(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("done456", "completed")],
                "pagination": {"has_more": False},
            }
        )
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["total_projected"], 0)

    def test_historical_failed_task_without_current_surface_is_omitted(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("failed1", "failed")],
                "pagination": {"has_more": False},
            }
        )
        self.assertEqual(result["count"], 0)

    def test_explicit_task_attention_evidence_keeps_terminal_failure_visible(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [
                    task(
                        "failed2",
                        "failed",
                        action_required=True,
                        action_reason="lifecycle-receipt-missing",
                    )
                ],
                "pagination": {"has_more": False},
            }
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn("lifecycle-receipt-missing", group["action_reasons"])

    def test_outcome_unknown_remains_attention_without_other_surface(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("unknown1", "outcome_unknown")],
                "pagination": {"has_more": False},
            }
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn("task-outcome_unknown", group["action_reasons"])

    def test_worker_attention_is_preserved(self) -> None:
        result = project(
            browser_payload={
                "workers": [
                    worker(
                        "0123456789abcdefabcd",
                        state="interrupted",
                        action_required=True,
                        reason="systemd-observation-ambiguous",
                    )
                ],
                "has_more": False,
            }
        )
        group = result["work"][0]
        self.assertEqual(group["binding_status"], "authority-bound")
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn("systemd-observation-ambiguous", group["action_reasons"])

    def test_workspace_lease_binds_tmux_and_process(self) -> None:
        workspace = "gaw-bound-1"
        result = project(
            resources_payload={
                "leases": [
                    lease(
                        f"agent-workspace:{workspace}",
                        f"workspace:{workspace}",
                    )
                ],
                "count": 1,
                "truncated": False,
            },
            tmux_payload={"returncode": 0, "stdout": f"{workspace}\t4\t0\t80\n"},
            process_payload={
                "returncode": 0,
                "lines": [
                    "123 1 S 10 python3 -m grabowski_agent_workspace pane "
                    f"{workspace} writer --secret token"
                ],
            },
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"workspace:{workspace}")
        self.assertEqual(group["binding_status"], "lease-bound")
        self.assertEqual(group["projection_state"], "active")
        self.assertEqual(len(group["physical_refs"]["tmux_sessions"]), 1)
        self.assertEqual(len(group["physical_refs"]["processes"]), 1)
        serialized = str(result)
        self.assertNotIn("--secret", serialized)
        self.assertNotIn("token", serialized)

    def test_physical_only_workspace_is_attention_not_active(self) -> None:
        workspace = "gaw-orphan-1"
        result = project(
            tmux_payload={"returncode": 0, "stdout": f"{workspace}\t4\t0\t80\n"},
            process_payload={
                "returncode": 0,
                "lines": [
                    "124 1 S 11 python3 -m grabowski_agent_workspace pane "
                    f"{workspace} tests"
                ],
            },
        )
        group = result["work"][0]
        self.assertEqual(group["binding_status"], "physical-only")
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn(
            "physical-workspace-without-authority", group["action_reasons"]
        )

    def test_unbound_tmux_and_coding_agent_are_samples_only(self) -> None:
        result = project(
            tmux_payload={"returncode": 0, "stdout": "manual-shell\t1\t0\t70\n"},
            process_payload={
                "returncode": 0,
                "lines": [
                    "200 1 S 12 claude claude --api-key very-secret prompt text"
                ],
            },
        )
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["unbound_physical"]["tmux_total_unbound"], 1)
        self.assertEqual(result["unbound_physical"]["process_total_unbound"], 1)
        process_sample = result["unbound_physical"]["processes"][0]
        self.assertEqual(process_sample["executable"], "claude")
        self.assertNotIn("arguments", process_sample)
        self.assertNotIn("very-secret", str(result))

    def test_dirty_unbound_checkout_is_attention(self) -> None:
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "dirty-one",
                            "/home/alex/repos/.worktrees/dirty-one",
                            dirty=True,
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["binding_status"], "checkout-bound")
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn("dirty-checkout", group["action_reasons"])

    def test_clean_unbound_checkout_is_not_current_work(self) -> None:
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "clean-old",
                            "/home/alex/repos/.worktrees/clean-old",
                            lifecycle_state="unclassified_clean",
                        )
                    ],
                }
            ]
        )
        self.assertEqual(result["count"], 0)

    def test_cleanup_candidate_is_attention(self) -> None:
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "cleanup-one",
                            "/home/alex/repos/.worktrees/cleanup-one",
                            cleanup_candidate=True,
                            lifecycle_state="cleanup_candidate",
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "attention")
        self.assertIn("cleanup-candidate", group["action_reasons"])

    def test_dirty_main_checkout_is_attention(self) -> None:
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "main-dirty",
                            REPOSITORY,
                            dirty=True,
                            is_main=True,
                            lifecycle_state="main",
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertIn("dirty-main-checkout", group["action_reasons"])

    def test_unbound_checkout_process_is_physical_attention(self) -> None:
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "physical-one",
                            "/home/alex/repos/.worktrees/physical-one",
                            processes=[{"pid": 88, "command": "python3"}],
                            lifecycle_state="unclassified_clean",
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["binding_status"], "physical-only")
        self.assertIn(
            "physical-checkout-without-authority", group["action_reasons"]
        )

    def test_ambiguous_checkout_binding_is_explicit(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("taska"), task("taskb")],
                "pagination": {"has_more": False},
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "ambiguous-one",
                            "/home/alex/repos/grabowski",
                            task_ids=["taska", "taskb"],
                        )
                    ],
                }
            ],
        )
        groups = {item["work_id"]: item for item in result["work"]}
        attached = [item for item in groups.values() if item["checkout_refs"]]
        self.assertEqual(len(attached), 1)
        self.assertEqual(attached[0]["binding_status"], "ambiguous")
        self.assertEqual(len(attached[0]["related_work_ids"]), 1)

    def test_pagination_is_snapshot_bound_and_deterministic(self) -> None:
        tasks = [task("task1", updated=30), task("task2", updated=20)]
        first = project(
            tasks_payload={"tasks": tasks, "pagination": {"has_more": False}},
            limit=1,
        )
        self.assertTrue(first["pagination"]["has_more"])
        second = project(
            tasks_payload={"tasks": tasks, "pagination": {"has_more": False}},
            limit=1,
            cursor=first["pagination"]["next_cursor"],
        )
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertNotEqual(first["work"][0]["work_id"], second["work"][0]["work_id"])
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError, "another live snapshot"
        ):
            project(
                tasks_payload={
                    "tasks": [task("task1", updated=31), task("task2", updated=20)],
                    "pagination": {"has_more": False},
                },
                limit=1,
                cursor=first["pagination"]["next_cursor"],
            )

    def test_repository_filter_is_required_and_enforced(self) -> None:
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError, "between 1 and"
        ):
            project(repository_filters=[])
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError, "outside repository_filters"
        ):
            project(
                checkout_payloads=[
                    {"repository": "/other/repo", "worktrees": []}
                ]
            )

    def test_truncation_and_source_errors_are_visible(self) -> None:
        result = project(
            tasks_payload={"tasks": [], "pagination": {"has_more": True}},
            resources_payload={"leases": [], "count": 2, "truncated": False},
            browser_payload={"workers": [], "has_more": True},
            source_errors=[{"source": "checkout", "error": "unavailable"}],
        )
        self.assertTrue(result["source_truncation"]["tasks"])
        self.assertTrue(result["source_truncation"]["resources"])
        self.assertTrue(result["source_truncation"]["browser_workers"])
        self.assertEqual(result["source_errors"][0]["source"], "checkout")
        self.assertIn("truncated", result["warnings"][0])

    def test_malformed_physical_records_are_visible_not_fatal(self) -> None:
        result = project(
            tmux_payload={"returncode": 0, "stdout": "broken\n"},
            process_payload={"returncode": 0, "lines": ["bad process"]},
        )
        sources = {item["source"] for item in result["source_errors"]}
        self.assertEqual(sources, {"tmux", "processes"})
        self.assertEqual(result["count"], 0)

    def test_invalid_source_shapes_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError, "pagination must be an object"
        ):
            project(tasks_payload={"tasks": [], "pagination": []})
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError, "resources.count"
        ):
            project(resources_payload={"leases": [], "count": "many"})
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError, "entry_count"
        ):
            project(
                checkout_payloads=[
                    {
                        "repository": REPOSITORY,
                        "worktrees": [
                            {
                                **checkout("bad-count", "/tmp/bad"),
                                "status": {"dirty": False, "entry_count": "one"},
                            }
                        ],
                    }
                ]
            )

    def test_output_declares_non_authoritative_boundary(self) -> None:
        result = project()
        boundaries = " ".join(result["does_not_establish"])
        self.assertIn("new task", boundaries)
        self.assertIn("permission to stop", boundaries)
        self.assertEqual(result["recommended_next_action"], "none")


if __name__ == "__main__":
    unittest.main()

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
    resource_keys: list[str] | None = None,
) -> dict:
    return {
        "task_id": task_id,
        "state": state,
        "host": "heim-pc",
        "unit": f"grabowski-task-{task_id}.service",
        "cwd": cwd,
        "lease_owner_id": f"task:{task_id}",
        "resource_keys": resource_keys or [],
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
    binding_owner: str | None = None,
    binding_phase: str | None = None,
    binding_consistent: bool = True,
    retention_active: bool = False,
    drift_reasons: list[str] | None = None,
) -> dict:
    binding = (
        {
            "owner_id": binding_owner,
            "phase": binding_phase,
            "source": {"kind": "bureau-task", "id": "T095"},
        }
        if binding_owner is not None
        else None
    )
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
                {"owner_id": item, "resource_key": f"path:{path}"}
                for item in owner_ids or []
            ],
            "processes": processes or [],
        },
        "lifecycle": {"state": lifecycle_state, "binding": binding},
        "lifecycle_state": lifecycle_state,
        "lifecycle_decision": {
            "binding_present": binding is not None,
            "binding_phase": binding_phase,
            "binding_consistent": binding_consistent,
            "binding_drift_reasons": drift_reasons or [],
            "retention_active": retention_active,
        },
        "cleanup_candidate": cleanup_candidate,
    }




def attention(
    task_id: str,
    classification: str,
    *,
    state: str = "failed",
    decision: str | None = None,
) -> dict:
    return {
        "task_id": task_id,
        "attempt": 1,
        "state": state,
        "classification": classification,
        "decision": decision,
        "authority": "bureau:test",
        "evidence_ref": f"evidence:{task_id}",
        "outcome_receipt_sha256": "a" * 64,
        "evidence_error": None,
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
        "attention_payload": {"records": [], "pagination": {"has_more": False}},
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
                            owner_ids=[f"task:{task_id}"],
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
        self.assertEqual(group["projection_state"], "blocking")
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
                "tasks": [task("failed2", "failed")],
                "pagination": {"has_more": False},
            },
            attention_payload={
                "records": [attention("failed2", "invalid_evidence")],
                "pagination": {"has_more": False},
            },
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn("attention-invalid_evidence", group["action_reasons"])
        self.assertTrue(
            any(ref["source"] == "task-attention-decision-evidence" for ref in group["authority_refs"])
        )

    def test_outcome_unknown_remains_attention_without_other_surface(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("unknown1", "outcome_unknown")],
                "pagination": {"has_more": False},
            }
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "blocking")
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
        self.assertEqual(group["projection_state"], "blocking")
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
        self.assertEqual(group["projection_state"], "unknown")
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
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn("dirty-checkout", group["action_reasons"])

    def test_dirty_checkout_with_exact_live_operation_lease_is_active(self) -> None:
        owner = "operator:active-edit"
        path = "/home/alex/repos/.worktrees/active-edit"
        result = project(
            resources_payload={
                "leases": [lease(owner, f"path:{path}")],
                "count": 1,
                "truncated": False,
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "active-edit",
                            path,
                            dirty=True,
                            owner_ids=[owner],
                        )
                    ],
                }
            ],
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"operation:{owner}")
        self.assertEqual(group["projection_state"], "active")
        self.assertFalse(group["action_required"])
        self.assertNotIn("dirty-checkout", group["action_reasons"])

    def test_dirty_main_checkout_with_exact_live_operation_lease_remains_blocking(self) -> None:
        owner = "operator:main-edit"
        path = REPOSITORY
        record = checkout("main", path, dirty=True, owner_ids=[owner])
        record["is_main"] = True
        result = project(
            resources_payload={
                "leases": [lease(owner, f"path:{path}")],
                "count": 1,
                "truncated": False,
            },
            checkout_payloads=[
                {"repository": REPOSITORY, "worktrees": [record]}
            ],
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"operation:{owner}")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertTrue(group["action_required"])
        self.assertIn("dirty-main-checkout", group["action_reasons"])

    def test_dirty_retained_checkout_with_unrelated_live_lease_remains_blocking(self) -> None:
        owner = "operator:retained-edit"
        path = "/home/alex/repos/.worktrees/retained-edit"
        record = checkout("retained-edit", path, dirty=True)
        record["lifecycle"]["retention"] = {"owner_id": owner}
        result = project(
            resources_payload={
                "leases": [lease(owner, "path:/home/alex/repos/.worktrees/other-edit")],
                "count": 1,
                "truncated": False,
            },
            checkout_payloads=[
                {"repository": REPOSITORY, "worktrees": [record]}
            ],
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"operation:{owner}")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertTrue(group["action_required"])
        self.assertIn("dirty-checkout", group["action_reasons"])

    def test_dirty_checkout_bound_to_terminal_task_remains_blocking(self) -> None:
        task_id = "terminal-edit"
        path = "/home/alex/repos/.worktrees/terminal-edit"
        result = project(
            tasks_payload={
                "tasks": [
                    task(
                        task_id,
                        "completed",
                        cwd=path,
                        resource_keys=[f"path:{path}"],
                    )
                ],
                "pagination": {"has_more": False},
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "terminal-edit",
                            path,
                            dirty=True,
                            task_ids=[task_id],
                        )
                    ],
                }
            ],
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"task:{task_id}")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertTrue(group["action_required"])
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
        self.assertEqual(group["projection_state"], "blocking")
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
                            owner_ids=["task:taska", "task:taskb"],
                            blocking=True,
                        )
                    ],
                }
            ],
        )
        groups = {item["work_id"]: item for item in result["work"]}
        attached = [item for item in groups.values() if item["checkout_refs"]]
        self.assertEqual(len(attached), 1)
        self.assertEqual(attached[0]["binding_status"], "ambiguous")
        self.assertEqual(set(attached[0]["related_work_ids"]), {"task:taska", "task:taskb"})

    def test_managed_active_checkout_with_retention_is_active(self) -> None:
        owner = "operator:managed-active"
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "managed-active",
                            "/home/alex/repos/.worktrees/managed-active",
                            lifecycle_state="retained",
                            binding_owner=owner,
                            binding_phase="active",
                            retention_active=True,
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"operation:{owner}")
        self.assertEqual(group["projection_state"], "active")
        binding_ref = next(
            ref for ref in group["authority_refs"]
            if ref["source"] == "checkout-lifecycle-binding"
        )
        self.assertEqual(binding_ref["phase"], "active")
        self.assertTrue(binding_ref["consistent"])

    def test_managed_active_checkout_without_retention_is_blocking(self) -> None:
        owner = "operator:managed-expired"
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "managed-expired",
                            "/home/alex/repos/.worktrees/managed-expired",
                            lifecycle_state="managed_active_attention",
                            binding_owner=owner,
                            binding_phase="active",
                            retention_active=False,
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn(
            "managed-active-lifecycle-attention", group["action_reasons"]
        )

    def test_managed_lifecycle_drift_is_fail_closed_and_explained(self) -> None:
        owner = "operator:managed-drift"
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "managed-drift",
                            "/home/alex/repos/.worktrees/managed-drift",
                            lifecycle_state="managed_lifecycle_drift",
                            binding_owner=owner,
                            binding_phase="archived",
                            binding_consistent=False,
                            drift_reasons=[
                                "archived-binding-without-matching-open-archive"
                            ],
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn("managed-lifecycle-drift", group["action_reasons"])
        self.assertIn(
            "archived-binding-without-matching-open-archive",
            group["action_reasons"],
        )

    def test_inconsistent_binding_does_not_establish_owner_authority(self) -> None:
        claimed_owner = "operator:claimed-by-drift"
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "managed-drift-owner",
                            "/home/alex/repos/.worktrees/managed-drift-owner",
                            lifecycle_state="managed_lifecycle_drift",
                            binding_owner=claimed_owner,
                            binding_phase="active",
                            binding_consistent=False,
                            drift_reasons=["binding-retention-owner-mismatch"],
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], "checkout:managed-drift-owner")
        self.assertEqual(group["binding_status"], "checkout-bound")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertFalse(
            any(
                ref.get("source") == "checkout-lifecycle-binding"
                for ref in group["authority_refs"]
            )
        )
        drift_ref = next(
            ref
            for ref in group["heuristic_refs"]
            if ref.get("kind") == "checkout-lifecycle-binding-drift"
        )
        self.assertEqual(drift_ref["owner_id"], claimed_owner)
        self.assertFalse(drift_ref["authority"])

    def test_binding_decision_must_match_lifecycle_binding(self) -> None:
        record = checkout(
            "binding-envelope-mismatch",
            "/home/alex/repos/.worktrees/binding-envelope-mismatch",
            binding_owner="operator:binding-envelope",
            binding_phase="active",
            retention_active=True,
        )
        record["lifecycle_decision"]["binding_present"] = False
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError,
            "binding presence disagrees",
        ):
            project(
                checkout_payloads=[
                    {"repository": REPOSITORY, "worktrees": [record]}
                ]
            )

    def test_binding_phase_cannot_be_synthesized_without_binding(self) -> None:
        record = checkout(
            "synthetic-terminal-binding",
            "/home/alex/repos/.worktrees/synthetic-terminal-binding",
        )
        record["lifecycle_decision"]["binding_phase"] = "archived"
        with self.assertRaisesRegex(
            current_work.CurrentWorkProjectionError,
            "binding phase requires",
        ):
            project(
                checkout_payloads=[
                    {"repository": REPOSITORY, "worktrees": [record]}
                ]
            )

    def test_dirty_managed_drift_remains_blocking_despite_exact_live_lease(self) -> None:
        owner = "operator:dirty-managed-drift"
        path = "/home/alex/repos/.worktrees/dirty-managed-drift"
        result = project(
            resources_payload={
                "leases": [lease(owner, f"path:{path}")],
                "count": 1,
                "truncated": False,
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "dirty-managed-drift",
                            path,
                            dirty=True,
                            owner_ids=[owner],
                            binding_owner=owner,
                            binding_phase="active",
                            binding_consistent=False,
                            drift_reasons=["binding-retention-owner-mismatch"],
                        )
                    ],
                }
            ],
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn("managed-lifecycle-drift", group["action_reasons"])
        self.assertIn("binding-retention-owner-mismatch", group["action_reasons"])

    def test_archived_cleanup_candidate_is_closed_not_cleaned_without_task(self) -> None:
        owner = "operator:archived-cleanup"
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "archived-cleanup",
                            "/home/alex/repos/.worktrees/archived-cleanup",
                            cleanup_candidate=True,
                            lifecycle_state="cleanup_candidate",
                            binding_owner=owner,
                            binding_phase="archived",
                            binding_consistent=True,
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "blocking")
        self.assertEqual(group["convergence_stage"], "closed-not-cleaned")
        self.assertTrue(result["convergence_summary"]["finishable_chain_prioritized"])

    def test_completed_retained_checkout_is_prioritized_closed_not_cleaned(self) -> None:
        owner = "operator:managed-terminal"
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "managed-terminal",
                            "/home/alex/repos/.worktrees/managed-terminal",
                            lifecycle_state="completed_retained",
                            binding_owner=owner,
                            binding_phase="completed_retained",
                            binding_consistent=True,
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "terminal_archived")
        self.assertIn("closed-not-cleaned", group["action_reasons"])
        self.assertEqual(group["convergence_stage"], "closed-not-cleaned")
        self.assertTrue(result["convergence_summary"]["finishable_chain_prioritized"])

    def test_pagination_is_snapshot_bound_and_deterministic(self) -> None:
        tasks = [task("task1", updated=30), task("task2", updated=20)]
        first = project(
            tasks_payload={"tasks": tasks, "pagination": {"has_more": False}},
            limit=1,
        )
        self.assertTrue(first["pagination"]["has_more"])
        second = project(
            tasks_payload={"tasks": tasks, "pagination": {"has_more": False}},
            generated_at_unix=101,
            limit=1,
            cursor=first["pagination"]["next_cursor"],
        )
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertEqual(first["work"][0]["observation"]["observed_at_unix"], 100)
        self.assertEqual(second["work"][0]["observation"]["observed_at_unix"], 101)
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

    def test_pagination_ignores_process_elapsed_time_but_preserves_it_in_output(self) -> None:
        tasks = [task("task-a", updated=20), task("task-b", updated=10)]
        first = project(
            tasks_payload={"tasks": tasks, "pagination": {"has_more": False}},
            process_payload={
                "returncode": 0,
                "lines": ["123 1 S 10 codex codex exec"],
            },
            limit=1,
        )
        self.assertTrue(first["pagination"]["has_more"])
        self.assertEqual(first["unbound_physical"]["processes"][0]["elapsed_seconds"], 10)
        second = project(
            tasks_payload={"tasks": tasks, "pagination": {"has_more": False}},
            process_payload={
                "returncode": 0,
                "lines": ["123 1 R 11 codex codex exec"],
            },
            generated_at_unix=101,
            limit=1,
            cursor=first["pagination"]["next_cursor"],
        )
        self.assertEqual(first["snapshot_sha256"], second["snapshot_sha256"])
        self.assertEqual(second["unbound_physical"]["processes"][0]["elapsed_seconds"], 11)

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


    def test_closed_attention_is_archived_from_current_but_visible_in_history(self) -> None:
        task_payload = {
            "tasks": [task("closed1", "failed")],
            "pagination": {"has_more": False},
        }
        attention_payload = {
            "records": [attention("closed1", "decision_closed", decision="closed")],
            "pagination": {"has_more": False},
        }
        current = project(tasks_payload=task_payload, attention_payload=attention_payload)
        history = project(
            tasks_payload=task_payload,
            attention_payload=attention_payload,
            view="history",
        )
        self.assertEqual(current["total_projected"], 0)
        self.assertEqual(history["total_projected"], 1)
        self.assertEqual(history["work"][0]["projection_state"], "terminal_archived")
        self.assertIn("attention:decision_closed", history["work"][0]["source_states"])

    def test_deferred_attention_is_resumable(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("defer1", "failed")],
                "pagination": {"has_more": False},
            },
            attention_payload={
                "records": [attention("defer1", "decision_deferred", decision="deferred")],
                "pagination": {"has_more": False},
            },
        )
        self.assertEqual(result["state_counts"]["resumable"], 1)
        group = result["work"][0]
        self.assertEqual(group["projection_state"], "resumable")
        self.assertIn("attention-decision_deferred", group["action_reasons"])

    def test_task_typed_lease_remains_task_bound_when_task_sources_are_empty(self) -> None:
        task_id = "outside-bounded-task-window"
        result = project(
            resources_payload={
                "leases": [lease(f"task:{task_id}", f"path:/tmp/{task_id}")],
                "count": 1,
                "truncated": False,
            },
            tasks_payload={"tasks": [], "pagination": {"has_more": True}},
            attention_payload={"records": [], "pagination": {"has_more": True}},
        )
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"task:{task_id}")
        self.assertEqual(group["binding"]["kind"], "task")
        self.assertEqual(group["binding_status"], "lease-bound")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn("task-lifecycle-unresolved-for-live-lease", group["action_reasons"])
        self.assertEqual(group["observation"]["completeness"], "partial")
        self.assertEqual(result["total_projected_scope"], "bounded_source_snapshot")
        self.assertEqual(result["state_counts_scope"], "bounded_source_snapshot")

    def test_archived_attention_with_live_task_lease_is_blocking(self) -> None:
        task_id = "closed-live-lease"
        result = project(
            attention_payload={
                "records": [attention(task_id, "decision_closed", state="failed", decision="closed")],
                "pagination": {"has_more": False},
            },
            resources_payload={
                "leases": [lease(f"task:{task_id}", f"path:/tmp/{task_id}")],
                "count": 1,
                "truncated": False,
            },
        )
        self.assertEqual(result["total_projected"], 1)
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"task:{task_id}")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertIn("archived-attention-with-live-surfaces", group["action_reasons"])

    def test_attention_only_terminal_task_absorbs_task_owned_live_lease(self) -> None:
        task_id = "attention-lease-task"
        result = project(
            attention_payload={
                "records": [attention(task_id, "actionable", state="failed")],
                "pagination": {"has_more": False},
            },
            resources_payload={
                "leases": [lease(f"task:{task_id}", f"path:/tmp/{task_id}")],
                "count": 1,
                "truncated": False,
            },
        )
        self.assertEqual(result["total_projected"], 1)
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"task:{task_id}")
        self.assertEqual(group["projection_state"], "blocking")
        self.assertEqual(group["lease_summary"]["count"], 1)
        self.assertIn("attention-actionable", group["action_reasons"])

    def test_many_child_leases_keep_exact_aggregate_and_bounded_sample(self) -> None:
        owner = "operator:many-children"
        leases = [
            lease(owner, f"path:/tmp/current-work/{index}", updated=100 + index)
            for index in range(120)
        ]
        result = project(
            resources_payload={
                "leases": leases,
                "count": len(leases),
                "truncated": False,
            }
        )
        self.assertEqual(result["total_projected"], 1)
        group = result["work"][0]
        self.assertEqual(group["work_id"], f"operation:{owner}")
        self.assertEqual(group["lease_summary"]["count"], 120)
        self.assertEqual(group["lease_summary"]["resource_classes"], {"path": 120})
        self.assertEqual(len(group["lease_refs"]), current_work.MAX_EVIDENCE)
        self.assertTrue(group["lease_summary"]["sample_truncated"])
        self.assertEqual(group["surface_counts"]["leases"], 120)

    def test_shared_repository_leases_stay_separate_by_explicit_owner(self) -> None:
        first_owner = "operator:first-operation"
        second_owner = "operator:second-operation"
        result = project(
            resources_payload={
                "leases": [
                    lease(first_owner, f"repo:{REPOSITORY}:operation:first"),
                    lease(second_owner, f"repo:{REPOSITORY}:operation:second"),
                ],
                "count": 2,
                "truncated": False,
            }
        )
        groups = {item["work_id"]: item for item in result["work"]}
        self.assertEqual(
            set(groups),
            {f"operation:{first_owner}", f"operation:{second_owner}"},
        )
        self.assertEqual(groups[f"operation:{first_owner}"]["lease_summary"]["count"], 1)
        self.assertEqual(groups[f"operation:{second_owner}"]["lease_summary"]["count"], 1)
        self.assertEqual(
            groups[f"operation:{first_owner}"]["explicit_bindings"][0]["kind"],
            "operation",
        )

    def test_task_proximity_is_heuristic_and_never_checkout_authority(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("near1"), task("near2")],
                "pagination": {"has_more": False},
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "heuristic-one",
                            REPOSITORY,
                            task_ids=["near1", "near2"],
                            blocking=True,
                        )
                    ],
                }
            ],
        )
        checkout_group = next(item for item in result["work"] if item["checkout_refs"])
        self.assertEqual(checkout_group["work_id"], "checkout:heuristic-one")
        self.assertEqual(checkout_group["binding_status"], "checkout-bound")
        self.assertEqual(
            {ref["candidate_work_id"] for ref in checkout_group["heuristic_refs"]},
            {"task:near1", "task:near2"},
        )
        self.assertFalse(
            any(ref.get("source") == "task-ledger" for ref in checkout_group["authority_refs"])
        )
        self.assertIn("heuristic-relations-present", checkout_group["observation"]["uncertainty"]["reasons"])

    def test_source_truncation_marks_each_group_partial_with_uncertainty(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("partial1")],
                "pagination": {"has_more": True},
            },
            source_errors=[{"source": "tasks", "error": "unavailable"}],
        )
        group = result["work"][0]
        self.assertEqual(group["observation"]["completeness"], "partial")
        self.assertEqual(group["observation"]["uncertainty"]["level"], "medium")
        reasons = group["observation"]["uncertainty"]["reasons"]
        self.assertTrue(any(reason.startswith("truncated-sources:") for reason in reasons))
        self.assertIn("source-errors:tasks", reasons)

    def test_checkout_exposes_exact_path_and_branch_bindings_for_drilldown(self) -> None:
        result = project(
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "bound-path-branch",
                            "/home/alex/repos/.worktrees/bound-path-branch",
                            dirty=True,
                        )
                    ],
                }
            ]
        )
        group = result["work"][0]
        binding_kinds = {item["kind"] for item in group["explicit_bindings"]}
        self.assertEqual(binding_kinds, {"path", "branch"})
        self.assertEqual(
            group["drill_down_refs"][0],
            {"surface": "grabowski_checkout_inventory", "repository": REPOSITORY},
        )

    def test_convergence_recommendation_prioritizes_finishable_chains(self) -> None:
        # Construct a project with a closed-not-cleaned work group (terminal task with live surfaces/cleanup candidate)
        result = project(
            tasks_payload={
                "tasks": [task("t-done", state="completed", updated=50)],
                "pagination": {"has_more": False},
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "chk-candidate",
                            "/home/alex/repos/.worktrees/chk-candidate",
                            cleanup_candidate=True,
                            owner_ids=["task:t-done"],
                        )
                    ],
                }
            ],
        )
        self.assertIn("next_convergence_action", result)
        self.assertIn("reconcile terminal worktree hygiene and safe lifecycle reconciliation", result["next_convergence_action"])
        self.assertEqual(result["convergence_summary"]["primary_stage"], "closed-not-cleaned")
        self.assertTrue(result["convergence_summary"]["finishable_chain_prioritized"])
        self.assertEqual(result["convergence_summary"]["closed_not_cleaned_count"], 1)

    def test_generic_blocking_group_with_cleanup_candidate_is_blocking_not_closed_cleaned(self) -> None:
        result = project(
            tasks_payload={
                "tasks": [task("t-running", state="running", updated=50)],
                "pagination": {"has_more": False},
            },
            checkout_payloads=[
                {
                    "repository": REPOSITORY,
                    "worktrees": [
                        checkout(
                            "chk-candidate",
                            "/home/alex/repos/.worktrees/chk-candidate",
                            cleanup_candidate=True,
                            task_ids=["t-running"],
                        )
                    ],
                }
            ],
        )
        self.assertEqual(result["convergence_summary"]["primary_stage"], "blocking")
        self.assertEqual(result["convergence_summary"]["closed_not_cleaned_count"], 0)
        self.assertIn("inspect blocking work group", result["next_convergence_action"])


    def test_bound_present_reconciliation_does_not_duplicate_checkout(self) -> None:
        existing = checkout("key-a", "/tmp/work", dirty=True)
        result = project(
            checkout_payloads=[{"repository": REPOSITORY, "worktrees": [existing]}],
            reconciliation_payload={
                "bindings": [
                    {
                        "checkout_key": "key-a",
                        "state": "bound_present",
                        "blocking": False,
                        "reasons": [],
                    }
                ],
                "pagination": {"has_more": False},
            },
        )
        self.assertEqual(
            len([row for row in result["work"] if row["binding"]["id"] == "key-a"]),
            1,
        )
        self.assertFalse(
            any(
                item.get("source") == "checkout-binding-reconciliation"
                for item in result["work"][0]["heuristic_refs"]
            )
        )

    def test_orphaned_binding_projects_one_blocking_current_work_group(self) -> None:
        result = project(
            reconciliation_payload={
                "bindings": [
                    {
                        "checkout_key": "key-orphan",
                        "state": "orphaned_binding",
                        "blocking": True,
                        "reasons": ["binding-has-no-current-git-worktree-record"],
                        "binding_identity": {"checkout_key": "key-orphan"},
                        "worktree_identity": None,
                        "evidence": {"owner_id": "operator:test"},
                        "recommended_next_step": "inspect_git_and_binding_history_without_mutation",
                    }
                ],
                "pagination": {"has_more": False},
            },
        )
        self.assertEqual(result["count"], 1)
        row = result["work"][0]
        self.assertEqual(row["work_id"], "checkout-binding:key-orphan")
        self.assertEqual(row["binding_status"], "unbound")
        self.assertEqual(row["projection_state"], "blocking")
        self.assertIn("checkout-binding-orphaned_binding", row["action_reasons"])
        self.assertIn(
            "checkout_binding_reconciliation",
            row["observation"]["relevant_sources"],
        )

    def test_binding_drift_attaches_to_existing_checkout_without_duplicate(self) -> None:
        existing = checkout("key-a", "/tmp/work", dirty=False, lifecycle_state="active")
        result = project(
            checkout_payloads=[{"repository": REPOSITORY, "worktrees": [existing]}],
            reconciliation_payload={
                "bindings": [
                    {
                        "checkout_key": "key-a",
                        "state": "binding_identity_drift",
                        "blocking": True,
                        "reasons": ["checkout-path-mismatch"],
                        "binding_identity": {"checkout_key": "key-a"},
                        "worktree_identity": {"checkout_key": "key-a"},
                        "evidence": {"owner_id": "operator:test"},
                        "recommended_next_step": "reconcile_binding_identity_before_lifecycle_action",
                    }
                ],
                "pagination": {"has_more": False},
            },
        )
        matching = [row for row in result["work"] if row["binding"]["id"] == "key-a"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["projection_state"], "blocking")
        self.assertIn("checkout-path-mismatch", matching[0]["action_reasons"])


if __name__ == "__main__":
    unittest.main()


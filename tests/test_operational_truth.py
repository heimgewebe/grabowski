from __future__ import annotations

import hashlib
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_operational_truth as op_truth

REPOSITORY = "/home/alex/repos/grabowski"


def make_task(
    task_id: str,
    state: str = "running",
    *,
    cwd: str = REPOSITORY,
    updated: int = 20,
    unit: str = "",
    attempt: int = 1,
    argv_sha256: str = "a" * 64,
    execution_envelope_sha256: str = "b" * 64,
) -> dict:
    if len(task_id) != 24 or not re.fullmatch(r"[0-9a-f]{24}", task_id):
        task_id = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:24]
    return {
        "task_id": task_id,
        "state": state,
        "host": "heim-pc",
        "unit": unit or f"grabowski-task-{task_id}-a{attempt}.service",
        "cwd": cwd,
        "lease_owner_id": f"task:{task_id}",
        "argv_sha256": argv_sha256,
        "execution_envelope_sha256": execution_envelope_sha256,
        "attempt": attempt,
        "created_at_unix": 10,
        "updated_at_unix": updated,
        "recommended_next_action": "inspect",
        "action_required": False,
        "action_reason": "",
    }


def make_checkout(
    key: str,
    path: str,
    *,
    dirty: bool = False,
    blocking: bool = False,
    is_main: bool = False,
    owner_ids: list[str] | None = None,
    lifecycle_state: str = "active",
    binding_present: bool = True,
    binding_consistent: bool = True,
    drift_reasons: list[str] | None = None,
) -> dict:
    binding = (
        {"owner_id": "operator:test", "phase": "active", "source": {"kind": "test"}}
        if binding_present
        else None
    )
    effective_drift_reasons = (
        (drift_reasons or ["binding-owner-mismatch"])
        if not binding_consistent
        else []
    )
    lifecycle_decision = {
        "binding_present": binding_present,
        "binding_consistent": binding_consistent,
        "binding_phase": "active" if binding_present else None,
        "binding_drift_reasons": effective_drift_reasons,
        "retention_active": False,
        "cleanup_candidate": False,
        "remote_secured": True,
    }
    return {
        "checkout_key": key,
        "path": path,
        "head": "a" * 40,
        "branch": "feat/test",
        "is_main": is_main,
        "status": {"dirty": dirty, "entry_count": 1 if dirty else 0},
        "coordination": {
            "blocking": blocking,
            "tasks": [],
            "resource_leases": [
                {"owner_id": item, "resource_key": f"path:{path}"}
                for item in owner_ids or []
            ],
            "processes": [],
        },
        "lifecycle": {
            "state": lifecycle_state,
            "binding": binding,
            "retention": None,
        },
        "lifecycle_state": lifecycle_state,
        "lifecycle_decision": lifecycle_decision,
        "cleanup_candidate": False,
        "remote_secured": True,
    }


class OperationalTruthTests(unittest.TestCase):
    def test_active_versus_historical_blockers(self) -> None:
        active_t = make_task("000000000000000000000001", state="running")
        proj = op_truth.build_operational_truth_projection(
            tasks_payload={"tasks": [active_t]},
            repository_filters=[REPOSITORY],
        )
        self.assertGreaterEqual(proj["total_operational_blockers"], 1)
        blocker_ids = [b["work_id"] for b in proj["operational_blockers"]]
        self.assertIn("task:000000000000000000000001", blocker_ids)

        historical_checkout = make_checkout(
            "key-hist",
            "/tmp/hist-work",
            binding_consistent=False,
            drift_reasons=["binding-owner-mismatch"],
        )
        proj_hist = op_truth.build_operational_truth_projection(
            checkout_payloads=[{"repository": REPOSITORY, "worktrees": [historical_checkout]}],
            repository_filters=[REPOSITORY],
        )
        self.assertGreaterEqual(proj_hist["total_hygiene_items"], 1)
        hygiene_ids = [h["work_id"] for h in proj_hist["hygiene_projection"]["categories"]["historical_binding_deviations"]]
        self.assertIn("checkout:key-hist", hygiene_ids)

    def test_disjoint_dirty_states_versus_exact_overlap(self) -> None:
        foreign_dirty = make_checkout(
            "key-foreign",
            "/tmp/foreign-work",
            dirty=True,
            blocking=False,
        )
        proj_foreign = op_truth.build_operational_truth_projection(
            checkout_payloads=[{"repository": REPOSITORY, "worktrees": [foreign_dirty]}],
            repository_filters=[REPOSITORY],
        )
        self.assertEqual(proj_foreign["total_operational_blockers"], 0)
        self.assertGreaterEqual(proj_foreign["total_hygiene_items"], 1)

        overlapping_dirty = make_checkout(
            "key-overlap",
            "/tmp/overlap-work",
            dirty=True,
            blocking=True,
        )
        proj_overlap = op_truth.build_operational_truth_projection(
            checkout_payloads=[{"repository": REPOSITORY, "worktrees": [overlapping_dirty]}],
            repository_filters=[REPOSITORY],
        )
        self.assertEqual(proj_overlap["total_operational_blockers"], 1)

    def test_attention_exclusion_classes_and_outcome_unknown(self) -> None:
        unknown_t = make_task("0000000000000000000000a1", state="outcome_unknown")
        failed_t = make_task("0000000000000000000000f1", state="failed")
        failed_t["failure_classification"] = "expected_red"

        proj = op_truth.build_operational_truth_projection(
            tasks_payload={"tasks": [unknown_t, failed_t]},
            attention_payload={"tasks": [unknown_t, failed_t]},
            repository_filters=[REPOSITORY],
        )
        att = proj["actionable_attention"]
        self.assertEqual(att["raw_attention_count"], 2)
        self.assertEqual(att["current_attention_count"], 1)
        self.assertEqual(att["excluded_attention_count"], 1)
        self.assertEqual(att["excluded_classification_counts"].get("expected_red"), 1)

    def test_unbound_process_versus_exact_binding(self) -> None:
        unbound_proc = {
            "pid": 9999,
            "ppid": 1,
            "command": "python -m grabowski_agent_workspace pane unknown",
            "command_class": "coding-agent",
            "workspace_id": None,
        }
        proj = op_truth.build_operational_truth_projection(
            process_payload={"processes": [unbound_proc], "truncated": False},
            repository_filters=[REPOSITORY],
        )
        self.assertIn("unbound_physical_surfaces", proj["hygiene_projection"])

    def test_operation_identity_reuse(self) -> None:
        t1 = make_task("000000000000000000000101", state="running", unit="worker.service", argv_sha256="c" * 64)
        t2 = make_task("000000000000000000000102", state="running", unit="worker.service", argv_sha256="c" * 64)
        proj = op_truth.build_operational_truth_projection(
            tasks_payload={"tasks": [t1, t2]},
            repository_filters=[REPOSITORY],
        )
        self.assertGreaterEqual(len(proj["reused_operation_identities"]), 1)

    def test_pagination_and_missing_sources(self) -> None:
        t1 = make_task("0000000000000000000000b1", state="running")
        t2 = make_task("0000000000000000000000b2", state="running")
        proj_p1 = op_truth.build_operational_truth_projection(
            tasks_payload={"tasks": [t1, t2]},
            repository_filters=[REPOSITORY],
            limit=1,
        )
        self.assertEqual(proj_p1["count"], 1)
        self.assertTrue(proj_p1["pagination"]["has_more"])
        next_cursor = proj_p1["pagination"]["next_cursor"]
        self.assertIsNotNone(next_cursor)

        proj_p2 = op_truth.build_operational_truth_projection(
            tasks_payload={"tasks": [t1, t2]},
            repository_filters=[REPOSITORY],
            limit=1,
            cursor=next_cursor,
        )
        self.assertEqual(proj_p2["count"], 1)
        self.assertFalse(proj_p2["pagination"]["has_more"])

    def test_hygiene_projection_view(self) -> None:
        foreign_dirty = make_checkout(
            "key-hyg",
            "/tmp/hyg-work",
            dirty=True,
            blocking=False,
        )
        hyg_proj = op_truth.build_hygiene_projection(
            checkout_payloads=[{"repository": REPOSITORY, "worktrees": [foreign_dirty]}],
            repository_filters=[REPOSITORY],
        )
        self.assertEqual(hyg_proj["view"], "hygiene")
        self.assertEqual(hyg_proj["projection"], "operational-truth")
        self.assertIn("hygiene_projection", hyg_proj)


if __name__ == "__main__":
    unittest.main()

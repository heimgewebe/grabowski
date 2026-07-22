from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_current_work_surface as surface


REPOSITORY = "/home/alex/repos/grabowski"


def task_payload() -> dict:
    return {
        "tasks": [
            {
                "task_id": "abc123",
                "state": "running",
                "attempt": 1,
                "host": "heim-pc",
                "unit": "grabowski-task-abc123.service",
                "cwd": REPOSITORY,
                "lease_owner_id": "task:abc123",
                "resource_keys": [],
                "created_at_unix": 10,
                "updated_at_unix": 20,
                "recommended_next_action": "inspect",
            }
        ],
        "pagination": {"has_more": False},
    }


class CurrentWorkSurfaceTests(unittest.TestCase):
    def test_surface_collects_sources_without_creating_a_second_truth(self) -> None:
        operator = SimpleNamespace(_require_operator_capability=lambda capability: None)
        with patch.object(surface, "_operator", return_value=operator), patch.object(
            surface, "_task_payload", return_value=task_payload()
        ), patch.object(
            surface,
            "_attention_payload",
            return_value={"records": [], "pagination": {"has_more": False}},
        ), patch.object(
            surface,
            "_resources_payload",
            return_value={"leases": [], "count": 0, "truncated": False},
        ), patch.object(
            surface,
            "_checkout_payloads",
            return_value=[{"repository": REPOSITORY, "worktrees": []}],
        ), patch.object(
            surface, "_tmux_payload", return_value={"returncode": 0, "stdout": ""}
        ), patch.object(
            surface, "_process_payload", return_value={"returncode": 0, "lines": []}
        ), patch.object(
            surface,
            "_worker_payload",
            side_effect=lambda kind, view: {"workers": [], "has_more": False},
        ):
            result = surface.grabowski_current_work([REPOSITORY])

        self.assertEqual(result["view"], "current")
        self.assertEqual(result["total_projected"], 1)
        self.assertEqual(result["work"][0]["work_id"], "task:abc123")
        self.assertIn(
            "a new independently mutable lifecycle or work-state truth",
            result["does_not_establish"],
        )

    def test_source_capability_failure_is_visible_as_partial_evidence(self) -> None:
        def gate(capability: str) -> None:
            if capability == "tmux_interaction":
                raise PermissionError("denied")

        operator = SimpleNamespace(_require_operator_capability=gate)
        with patch.object(surface, "_operator", return_value=operator), patch.object(
            surface, "_task_payload", return_value=task_payload()
        ), patch.object(
            surface,
            "_attention_payload",
            return_value={"records": [], "pagination": {"has_more": False}},
        ), patch.object(
            surface,
            "_resources_payload",
            return_value={"leases": [], "count": 0, "truncated": False},
        ), patch.object(
            surface,
            "_checkout_payloads",
            return_value=[{"repository": REPOSITORY, "worktrees": []}],
        ), patch.object(
            surface, "_process_payload", return_value={"returncode": 0, "lines": []}
        ), patch.object(
            surface,
            "_worker_payload",
            side_effect=lambda kind, view: {"workers": [], "has_more": False},
        ):
            result = surface.grabowski_current_work([REPOSITORY])

        self.assertTrue(any(item["source"] == "tmux" for item in result["source_errors"]))
        self.assertIn("one or more source surfaces returned errors or malformed records", result["warnings"])
        self.assertEqual(result["work"][0]["observation"]["completeness"], "complete")


    def test_task_lease_ids_are_bounded_and_deterministic(self) -> None:
        payload = {
            "leases": [
                {"owner_id": "task:z-task"},
                {"owner_id": "operator:other"},
                {"owner_id": "task:a-task"},
                {"owner_id": "task:z-task"},
            ]
        }
        task_ids, truncated = surface._task_lease_ids(payload)
        self.assertEqual(task_ids, ["a-task", "z-task"])
        self.assertFalse(truncated)

    def test_surface_requests_exact_lifecycle_for_task_owned_lease(self) -> None:
        operator = SimpleNamespace(_require_operator_capability=lambda capability: None)
        seen: dict[str, object] = {}

        def load_tasks(view: str, task_ids: list[str], *, required_ids_truncated: bool = False) -> dict:
            seen["view"] = view
            seen["task_ids"] = task_ids
            seen["required_ids_truncated"] = required_ids_truncated
            return task_payload()

        with patch.object(surface, "_operator", return_value=operator), patch.object(
            surface, "_resources_payload",
            return_value={
                "leases": [{"owner_id": "task:terminal123", "resource_key": "path:/tmp/x"}],
                "count": 1,
                "truncated": False,
            },
        ), patch.object(surface, "_task_payload", side_effect=load_tasks), patch.object(
            surface, "_attention_payload",
            return_value={"records": [], "pagination": {"has_more": False}},
        ), patch.object(
            surface, "_checkout_payloads",
            return_value=[{"repository": REPOSITORY, "worktrees": []}],
        ), patch.object(
            surface, "_tmux_payload", return_value={"returncode": 0, "stdout": ""}
        ), patch.object(
            surface, "_process_payload", return_value={"returncode": 0, "lines": []}
        ), patch.object(
            surface, "_worker_payload",
            side_effect=lambda kind, view: {"workers": [], "has_more": False},
        ):
            surface.grabowski_current_work([REPOSITORY])

        self.assertEqual(seen["view"], "current")
        self.assertEqual(seen["task_ids"], ["terminal123"])
        self.assertFalse(seen["required_ids_truncated"])

    def test_repository_scope_is_bounded_and_unique(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1 and"):
            surface.grabowski_current_work([])
        with self.assertRaisesRegex(ValueError, "unique"):
            surface.grabowski_current_work([REPOSITORY, REPOSITORY])


if __name__ == "__main__":
    unittest.main()

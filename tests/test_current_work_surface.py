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
            surface,
            "_reconciliation_payload",
            return_value={
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            },
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
        self.assertEqual(
            result["scope_contract"]["kind"],
            "mixed_global_and_repository_filtered",
        )
        self.assertFalse(result["scope_contract"]["repository_scoped_aggregates"])
        self.assertIn(
            "a new independently mutable lifecycle or work-state truth",
            result["does_not_establish"],
        )

    def test_scope_source_enumeration_matches_actual_collectors(self) -> None:
        seen_sources: list[str] = []

        def collect(
            source: str,
            _capability: str,
            loader: object,
            _errors: list[dict],
            _default: object,
        ) -> object:
            seen_sources.append(source)
            return loader()

        operator = SimpleNamespace(_require_operator_capability=lambda capability: None)
        with patch.object(surface, "_operator", return_value=operator), patch.object(
            surface, "_attempt_source", side_effect=collect
        ), patch.object(
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
            surface,
            "_reconciliation_payload",
            return_value={
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            },
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

        declared = set(result["scope_contract"]["global_sources"]) | set(
            result["scope_contract"]["repository_filtered_sources"]
        )
        self.assertEqual(set(seen_sources), declared)
        self.assertEqual(len(seen_sources), len(declared))

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
            surface,
            "_reconciliation_payload",
            return_value={
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            },
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
            surface,
            "_reconciliation_payload",
            return_value={
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            },
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

    def test_repository_scope_is_bounded_absolute_and_canonical(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 1 and"):
            surface.grabowski_current_work([])
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            surface.grabowski_current_work(["grabowski"])
        self.assertEqual(
            surface._require_repositories(["/home/alex/repos/../repos/grabowski"]),
            [REPOSITORY],
        )
        self.assertEqual(
            surface._require_repositories(["//home/alex/repos/grabowski"]),
            [REPOSITORY],
        )
        with self.assertRaisesRegex(ValueError, "unique canonical paths"):
            surface.grabowski_current_work(
                [REPOSITORY, "/home/alex/repos/../repos/grabowski"]
            )

    def test_checkout_source_uses_bounded_observation_contract(self) -> None:
        seen: dict[str, object] = {}

        def inventory(repository: str, **kwargs: object) -> dict:
            seen["repository"] = repository
            seen.update(kwargs)
            return {
                "repository": repository,
                "worktrees": [],
                "truncated": True,
                "omitted_worktree_count": 7,
                "probe_errors": [{"stage": "status"}],
            }

        errors: list[dict] = []
        checkouts = SimpleNamespace(checkout_inventory=inventory)
        with patch.object(surface, "_module", return_value=checkouts):
            payloads = surface._checkout_payloads([REPOSITORY], errors)

        self.assertEqual(payloads[0]["repository"], REPOSITORY)
        self.assertEqual(seen["repository"], REPOSITORY)
        self.assertFalse(seen["include_processes"])
        self.assertFalse(seen["include_tasks"])
        self.assertTrue(seen["include_resources"])
        self.assertEqual(
            seen["git_timeout_seconds"],
            surface.CURRENT_WORK_GIT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            seen["observation_budget_seconds"],
            surface.CURRENT_WORK_CHECKOUT_OBSERVATION_BUDGET_SECONDS,
        )
        self.assertEqual(
            seen["max_worktrees"],
            surface.CURRENT_WORK_CHECKOUT_MAX_WORKTREES,
        )
        self.assertEqual(
            errors,
            [
                {
                    "source": "checkouts",
                    "repository": REPOSITORY,
                    "error": "CheckoutObservationPartial",
                    "omitted_worktree_count": 7,
                    "probe_error_count": 1,
                }
            ],
        )

    def test_reconciliation_source_uses_bounded_git_timeout(self) -> None:
        seen: dict[str, object] = {}

        def reconcile(**kwargs: object) -> dict:
            seen.update(kwargs)
            return {
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            }

        reconciler = SimpleNamespace(
            MAX_PAGE_LIMIT=100,
            reconcile_checkout_bindings=reconcile,
        )
        with patch.object(surface, "_module", return_value=reconciler):
            result = surface._reconciliation_payload([REPOSITORY])

        self.assertEqual(result["bindings"], [])
        self.assertEqual(seen["repository_filters"], [REPOSITORY])
        self.assertEqual(seen["limit"], 100)
        self.assertEqual(
            seen["git_timeout_seconds"],
            surface.CURRENT_WORK_GIT_TIMEOUT_SECONDS,
        )

    def test_checkout_source_failure_is_isolated_per_repository(self) -> None:
        missing = "/home/alex/repos/missing"

        def inventory(repository: str, **_kwargs: object) -> dict:
            if repository == missing:
                raise ValueError("not a repository")
            return {"repository": repository, "worktrees": [{"path": repository}]}

        errors: list[dict] = []
        checkouts = SimpleNamespace(checkout_inventory=inventory)
        with patch.object(surface, "_module", return_value=checkouts):
            payloads = surface._checkout_payloads([REPOSITORY, missing], errors)

        self.assertEqual(payloads[0]["repository"], REPOSITORY)
        self.assertEqual(payloads[1], {"repository": missing, "worktrees": [], "truncated": True})
        self.assertEqual(
            errors,
            [{"source": "checkouts", "error": "ValueError", "repository": missing}],
        )


if __name__ == "__main__":
    unittest.main()

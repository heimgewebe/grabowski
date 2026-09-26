from __future__ import annotations

import sys
import threading
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
    def test_attention_payload_uses_bounded_projection_only_for_current_work(
        self,
    ) -> None:
        calls: list[tuple[dict, dict]] = []

        def reconcile(parameters: dict, **kwargs: object) -> dict:
            calls.append((parameters, kwargs))
            return {"records": [], "pagination": {"has_more": False}}

        fake_attention = SimpleNamespace(
            MAX_PAGE_LIMIT=100,
            reconcile_attention=reconcile,
        )
        with patch.object(surface, "_module", return_value=fake_attention):
            surface._attention_payload("current")
            surface._attention_payload("history")

        self.assertEqual(
            (
                {"limit": 100, "view": "current"},
                {"_bounded_current_projection": True},
            ),
            calls[0],
        )
        self.assertEqual(
            ({"limit": 100, "view": "history"}, {}),
            calls[1],
        )

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

    def test_independent_sources_overlap_without_dropping_evidence(self) -> None:
        operator = SimpleNamespace(_require_operator_capability=lambda capability: None)
        rendezvous = threading.Barrier(2)

        def overlap(value: object) -> object:
            rendezvous.wait(timeout=2)
            return value

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
            side_effect=lambda _repositories, _errors: overlap(
                [{"repository": REPOSITORY, "worktrees": []}]
            ),
        ), patch.object(
            surface,
            "_reconciliation_payload",
            return_value={
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            },
        ), patch.object(
            surface,
            "_tmux_payload",
            side_effect=lambda: overlap({"returncode": 0, "stdout": ""}),
        ), patch.object(
            surface, "_process_payload", return_value={"returncode": 0, "lines": []}
        ), patch.object(
            surface,
            "_worker_payload",
            side_effect=lambda kind, view: {"workers": [], "has_more": False},
        ):
            result = surface.grabowski_current_work([REPOSITORY])

        overlapping_errors = [
            item
            for item in result["source_errors"]
            if item["source"] in {"checkouts", "tmux"}
        ]
        self.assertEqual(overlapping_errors, [])

    def test_attention_reads_after_task_generation_advances(self) -> None:
        operator = SimpleNamespace(_require_operator_capability=lambda capability: None)
        generation = {"value": 1}
        attention_generations: list[int] = []

        def load_tasks(
            _view: str,
            _task_ids: list[str],
            *,
            required_ids_truncated: bool = False,
        ) -> dict:
            self.assertFalse(required_ids_truncated)
            generation["value"] = 2
            payload = task_payload()
            payload["tasks"][0]["attempt"] = 2
            return payload

        def load_attention(_view: str) -> dict:
            attention_generations.append(generation["value"])
            return {"records": [], "pagination": {"has_more": False}}

        with patch.object(surface, "_operator", return_value=operator), patch.object(
            surface, "_task_payload", side_effect=load_tasks
        ), patch.object(
            surface, "_attention_payload", side_effect=load_attention
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

        self.assertEqual(attention_generations, [2])
        self.assertEqual(result["work"][0]["work_id"], "task:abc123")
        self.assertFalse(
            any(item["source"] == "attention" for item in result["source_errors"])
        )

    def test_checkout_reconciliation_waits_for_checkout_inventory(self) -> None:
        operator = SimpleNamespace(_require_operator_capability=lambda capability: None)
        checkout_finished = threading.Event()
        reconciliation_started = threading.Event()

        def load_checkouts(
            _repositories: list[str],
            _errors: list[dict],
        ) -> list[dict]:
            self.assertFalse(reconciliation_started.is_set())
            checkout_finished.set()
            return [{"repository": REPOSITORY, "worktrees": []}]

        def load_reconciliation(_repositories: list[str]) -> dict:
            self.assertTrue(checkout_finished.is_set())
            reconciliation_started.set()
            return {
                "bindings": [],
                "pagination": {"has_more": False},
                "total_count": 0,
            }

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
            surface, "_checkout_payloads", side_effect=load_checkouts
        ), patch.object(
            surface, "_reconciliation_payload", side_effect=load_reconciliation
        ), patch.object(
            surface, "_tmux_payload", return_value={"returncode": 0, "stdout": ""}
        ), patch.object(
            surface, "_process_payload", return_value={"returncode": 0, "lines": []}
        ), patch.object(
            surface,
            "_worker_payload",
            side_effect=lambda kind, view: {"workers": [], "has_more": False},
        ):
            surface.grabowski_current_work([REPOSITORY])

        self.assertTrue(checkout_finished.is_set())
        self.assertTrue(reconciliation_started.is_set())

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

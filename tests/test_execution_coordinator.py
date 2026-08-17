from __future__ import annotations

import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class _FakeFastMCP:
    def __init__(self, *args, **kwargs):
        pass

    def tool(self, *args, **kwargs):
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs):
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

coordinator = importlib.import_module("grabowski_execution_coordinator")


class ExecutionCoordinatorTests(unittest.TestCase):
    def status(
        self,
        *,
        writer_state: str = "completed",
        writer_terminal: bool = True,
        tests_state: str = "not_started",
        tests_terminal: bool = False,
        review_state: str = "not_started",
        review_terminal: bool = False,
        collection: dict | None = None,
        success_ready: bool = False,
        candidate_revision: dict | None = None,
        closed: bool = False,
        ownership_mode: str = "work_lane",
        task_start_intents: dict | None = None,
    ) -> dict:
        return {
            "closed": closed,
            "ownership_mode": ownership_mode,
            "creation_ready": True,
            "route_evidence_complete": True,
            "task_start_intents": {}
            if task_start_intents is None
            else task_start_intents,
            "tasks": {
                "writer": {
                    "task_id": "writer-task",
                    "state": writer_state,
                    "terminal": writer_terminal,
                },
                "tests": {
                    "task_id": None if tests_state == "not_started" else "tests-task",
                    "state": tests_state,
                    "terminal": tests_terminal,
                },
                "review": {
                    "task_id": None if review_state == "not_started" else "review-task",
                    "state": review_state,
                    "terminal": review_terminal,
                },
            },
            "collection": collection,
            "success_ready": success_ready,
            "candidate_revision": candidate_revision or {"eligible": False},
        }

    @staticmethod
    def complete_collection() -> dict:
        return {
            "state": "complete",
            "writer_head": "a" * 40,
            "diff_sha256": "b" * 64,
            "result_sha256": "c" * 64,
        }

    def test_closed_workspace_reduces_without_irrelevant_task_shape(self) -> None:
        decision = coordinator.reduce_status(
            {
                "ownership_mode": "work_lane",
                "closed": True,
            },
            revision_bound=False,
        )
        self.assertEqual(
            decision,
            {
                "action": "return",
                "state": "closed",
                "reason": "workspace_already_closed",
            },
        )

    def test_first_pass_happy_path_closes_verified_candidate(self) -> None:
        complete = self.complete_collection()
        statuses = [
            self.status(),
            self.status(tests_state="running", review_state="running"),
            self.status(
                tests_state="completed",
                tests_terminal=True,
                review_state="completed",
                review_terminal=True,
            ),
            self.status(
                tests_state="completed",
                tests_terminal=True,
                review_state="completed",
                review_terminal=True,
                collection=complete,
                success_ready=True,
            ),
            self.status(
                tests_state="completed",
                tests_terminal=True,
                review_state="completed",
                review_terminal=True,
                collection=complete,
                success_ready=True,
                closed=True,
            ),
        ]
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                side_effect=statuses,
            ),
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_collect",
                side_effect=[{"state": "collecting"}, {"state": "complete"}],
            ) as collect,
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_close",
                return_value={
                    "close_receipt": {
                        "state": "complete",
                        "closure_outcome": "successful",
                    }
                },
            ) as close,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-happy", max_polls=8, poll_seconds=0
            )

        self.assertEqual(result["state"], "verified_candidate_closed")
        self.assertEqual(result["reason"], "candidate_verified_and_workspace_closed")
        self.assertFalse(result["owns_state_store"])
        self.assertFalse(result["adoption_performed"])
        self.assertFalse(result["publication_performed"])
        self.assertEqual(
            [action["action"] for action in result["actions"]],
            ["collect", "collect", "close"],
        )
        self.assertEqual(collect.call_count, 2)
        close.assert_called_once_with(
            "gaw-happy",
            expected_head="a" * 40,
            expected_diff_sha256="b" * 64,
            expected_result_sha256="c" * 64,
            cancel_running=False,
            remove_tmux_session=True,
            abandon_failed_roles=False,
        )

    def test_requires_lane_backed_workspace_without_mutation(self) -> None:
        status = self.status(ownership_mode="legacy")
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                return_value=status,
            ),
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_collect"
            ) as collect,
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_writer_handoff"
            ) as handoff,
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_close"
            ) as close,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-legacy", max_polls=2, poll_seconds=0
            )

        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["reason"], "lane_backed_workspace_required")
        collect.assert_not_called()
        handoff.assert_not_called()
        close.assert_not_called()

    def test_status_failure_requires_reconciliation(self) -> None:
        with mock.patch.object(
            coordinator.workspace,
            "grabowski_agent_workspace_status",
            side_effect=RuntimeError("status unavailable"),
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-status", max_polls=2, poll_seconds=0
            )

        self.assertEqual(result["state"], "reconcile_required")
        self.assertEqual(result["reason"], "workspace_status_unobservable")
        self.assertIn("status unavailable", result["error"])

    def test_unknown_writer_outcome_is_never_retried(self) -> None:
        status = self.status(writer_state="outcome_unknown", writer_terminal=True)
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                return_value=status,
            ) as observe,
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_collect"
            ) as collect,
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_writer_handoff"
            ) as handoff,
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_close"
            ) as close,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-unknown", max_polls=4, poll_seconds=0
            )

        self.assertEqual(result["state"], "reconcile_required")
        self.assertEqual(result["reason"], "writer_outcome_requires_reconciliation")
        self.assertEqual(observe.call_count, 1)
        collect.assert_not_called()
        handoff.assert_not_called()
        close.assert_not_called()

    def test_candidate_revision_requires_explicit_command(self) -> None:
        status = self.status(
            collection=self.complete_collection(),
            candidate_revision={"eligible": True},
        )
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                return_value=status,
            ),
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_writer_handoff"
            ) as handoff,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-revision", max_polls=2, poll_seconds=0
            )

        self.assertEqual(result["state"], "revision_required")
        self.assertEqual(result["reason"], "candidate_revision_command_not_bound")
        handoff.assert_not_called()

    def test_runs_one_p4_bounded_candidate_revision_with_bound_argv(self) -> None:
        statuses = [
            self.status(
                collection=self.complete_collection(),
                candidate_revision={"eligible": True},
            ),
            self.status(writer_state="running", writer_terminal=False),
        ]
        command = ["codex", "exec", "apply revision request"]
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                side_effect=statuses,
            ),
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_writer_handoff",
                return_value={"state": "candidate_revision_started"},
            ) as handoff,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-revise",
                revision_argv=command,
                max_polls=2,
                poll_seconds=0,
            )

        self.assertEqual(result["state"], "pending")
        self.assertEqual(
            result["reason"], "poll_budget_exhausted_without_terminal_effect"
        )
        handoff.assert_called_once_with("gaw-revise", command)
        self.assertEqual(
            result["actions"],
            [{"action": "candidate_revision", "state": "candidate_revision_started"}],
        )

    def test_mutation_exception_reads_back_once_and_does_not_retry_effect(self) -> None:
        initial = self.status()
        readback = self.status(tests_state="running", review_state="running")
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                side_effect=[initial, readback],
            ) as observe,
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_collect",
                side_effect=RuntimeError("transport lost after call"),
            ) as collect,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-collect-unknown", max_polls=4, poll_seconds=0
            )

        self.assertEqual(result["state"], "reconcile_required")
        self.assertEqual(result["reason"], "collect_outcome_requires_reconciliation")
        self.assertEqual(observe.call_count, 2)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(result["status"], readback)

    def test_invalid_close_binding_refuses_close(self) -> None:
        collection = self.complete_collection()
        collection["writer_head"] = "not-a-head"
        status = self.status(collection=collection, success_ready=True)
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                return_value=status,
            ),
            mock.patch.object(
                coordinator.workspace, "grabowski_agent_workspace_close"
            ) as close,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-close-binding", max_polls=2, poll_seconds=0
            )

        self.assertEqual(result["state"], "reconcile_required")
        self.assertEqual(result["reason"], "collection_close_binding_invalid")
        close.assert_not_called()

    def test_existing_candidate_revision_start_intent_is_reconciled_once(self) -> None:
        statuses = [
            self.status(
                task_start_intents={
                    "writer_handoff": {
                        "kind": "candidate_revision",
                        "attempt": 2,
                    }
                }
            ),
            self.status(writer_state="running", writer_terminal=False),
        ]
        command = ["codex", "exec", "continue bound revision"]
        with (
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_status",
                side_effect=statuses,
            ),
            mock.patch.object(
                coordinator.workspace,
                "grabowski_agent_workspace_writer_handoff",
                return_value={"state": "candidate_revision_start_reconciled"},
            ) as handoff,
        ):
            result = coordinator.run_workspace_candidate_coordinator(
                "gaw-intent",
                revision_argv=command,
                max_polls=2,
                poll_seconds=0,
            )

        self.assertEqual(result["state"], "pending")
        handoff.assert_called_once_with("gaw-intent", command)
        self.assertEqual(
            result["actions"],
            [
                {
                    "action": "candidate_revision_reconcile",
                    "state": "candidate_revision_start_reconciled",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()

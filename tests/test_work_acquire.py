from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import grabowski_work_acquire as work_acquire

SHA = "a" * 40


class WorkAcquireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.target = self.root / "lane-worktree"
        self.state = self.root / "state"
        self.retention = int(time.time()) + 3600
        self.previous = os.environ.get("GRABOWSKI_WORK_LANE_ROOT")
        os.environ["GRABOWSKI_WORK_LANE_ROOT"] = str(self.state)
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        if self.previous is None:
            os.environ.pop("GRABOWSKI_WORK_LANE_ROOT", None)
        else:
            os.environ["GRABOWSKI_WORK_LANE_ROOT"] = self.previous

    def parameters(self) -> dict[str, object]:
        return {
            "source_kind": "direct-user",
            "source_id": "chat:authority-p0",
            "controller_actor": "chatgpt:controller",
            "scoped_writer_actor": "agent:writer",
            "repo": str(self.repo),
            "base_head": SHA,
            "branch": "feat/authority-p0",
            "target_path": str(self.target),
            "purpose": "direct user implementation lane",
            "retention_until_unix": self.retention,
            "idempotency_key": "authority-p0",
            "resource_keys": [],
            "ttl_seconds": 1200,
        }

    @staticmethod
    def acquired(owner: str, keys: list[str]) -> dict[str, object]:
        leases = [
            {
                "resource_key": key,
                "owner_id": owner,
                "purpose": "direct user implementation lane",
                "acquired_at_unix": int(time.time()),
                "updated_at_unix": int(time.time()),
                "expires_at_unix": int(time.time()) + 1200,
                "metadata_sha256": "d" * 64,
                "reclaimed_from_owner": None,
            }
            for key in keys
        ]
        return {"owner_id": owner, "leases": leases, "preserved": [], "reclaimed": []}

    def acquire(self, owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
        return self.acquired(owner, keys)

    def test_acquires_narrow_resources_and_returns_ready_lane(self) -> None:
        seen: dict[str, object] = {}
        def acquire(owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
            seen.update(owner=owner, keys=keys, kwargs=kwargs)
            return self.acquired(owner, keys)
        ensure = Mock(return_value={
            "result_state": "CREATED",
            "durable_receipt_sha256": "b" * 64,
            "post_state": {"target_registered": True, "target_path_exists": True},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=acquire,
            release_resources_fn=Mock(), inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["decision"], "AUTO_PREPARE_AND_EXECUTE")
        self.assertEqual(result["authority"]["scoped_writer"]["role"], "scoped_writer")
        self.assertIn(f"path:{self.target}", seen["keys"])
        self.assertIn(f"repo:{self.repo}:branch:feat/authority-p0", seen["keys"])
        self.assertNotIn(f"repo:{self.repo}", seen["keys"])
        self.assertEqual(
            result["inputs"]["system_convergence_plan"]["status"], "unclassified"
        )
        ensure.assert_called_once()
        ensure_parameters = ensure.call_args.args[0]
        self.assertIs(ensure_parameters["reposkop_required"], True)

    def test_supplied_system_convergence_plan_is_bound_into_lane_identity(self) -> None:
        planned = {
            "schema_version": 1,
            "kind": "grabowski.system_convergence_plan",
            "status": "planned",
            "systemic_closure_gate": "hard",
            "hard_gate_required": True,
            "admission_blocking": False,
            "plan_sha256": "f" * 64,
        }
        params = self.parameters()
        context = {
            "change_risk": "R2",
            "target_criticality": "essential",
            "expected_protocol_head": "d" * 40,
        }
        params["system_convergence"] = context
        with patch.object(
            work_acquire.work_admission,
            "plan_system_convergence",
            return_value=planned,
        ) as planner:
            result = work_acquire.acquire_work(
                params,
                acquire_resources_fn=self.acquire,
                release_resources_fn=Mock(),
                inspect_resource_fn=Mock(),
                ensure_worktree_fn=Mock(
                    return_value={
                        "result_state": "CREATED",
                        "durable_receipt_sha256": "b" * 64,
                        "post_state": {
                            "target_registered": True,
                            "target_path_exists": True,
                        },
                    }
                ),
                runner=Mock(),
            )
        planner.assert_called_once_with(context)
        self.assertEqual(result["inputs"]["system_convergence_plan"], planned)
        self.assertEqual(result["decision"], "AUTO_PREPARE_AND_EXECUTE")

    def test_write_paths_become_exact_repo_path_resources(self) -> None:
        seen: dict[str, object] = {}

        def acquire(owner: str, keys: list[str], **kwargs: object) -> dict[str, object]:
            seen.update(owner=owner, keys=keys, kwargs=kwargs)
            return self.acquired(owner, keys)

        params = self.parameters()
        params["write_paths"] = [
            "src/feature.py",
            str(self.repo / "tests" / "test_feature.py"),
        ]
        work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
        )
        self.assertIn(f"path:{self.repo / 'src' / 'feature.py'}", seen["keys"])
        self.assertIn(
            f"path:{self.repo / 'tests' / 'test_feature.py'}", seen["keys"]
        )
        self.assertNotIn(f"repo:{self.repo}", seen["keys"])

    @staticmethod
    def writer_result(target: Path) -> dict[str, object]:
        return {
            "job_id": "job-123",
            "unit": "grabowski-job-123456789abc",
            "owner": "job:grabowski-job-123456789abc",
            "argv_sha256": "e" * 64,
            "cwd": str(target),
            "runtime_seconds": 600,
            "metadata_path": "/tmp/job/metadata.json",
            "expected_receipt": {
                "finalization_path": "/tmp/job/finalization.json"
            },
            "final_status": "launch_submitted",
        }

    def test_optional_scoped_writer_starts_and_binds_durable_job(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        start = Mock(return_value=self.writer_result(self.target))
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
            start_writer_fn=start,
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["next_action"], "writer_started")
        self.assertEqual(
            result["writer_job"]["unit"], "grabowski-job-123456789abc"
        )
        self.assertEqual(result["writer_start"]["state"], "started")
        self.assertNotIn("scoped_writer_argv", result["inputs"])
        start.assert_called_once_with(
            ["writer", "--once"], cwd=str(self.target), runtime_seconds=600
        )

    def test_identical_writer_replay_renews_lane_without_second_job(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        start = Mock(return_value=self.writer_result(self.target))
        acquire = Mock(side_effect=self.acquire)
        ensure = Mock(
            side_effect=[
                {
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                },
                {
                    "result_state": "ALREADY_CORRECT",
                    "durable_receipt_sha256": "c" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                },
            ]
        )
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": Mock(),
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
            "start_writer_fn": start,
        }
        first = work_acquire.acquire_work(params, **kwargs)
        second = work_acquire.acquire_work(params, **kwargs)
        self.assertEqual(first["writer_job"], second["writer_job"])
        self.assertEqual(second["writer_start"]["state"], "reused")
        self.assertTrue(second["replayed"])
        self.assertEqual(start.call_count, 1)
        self.assertEqual(acquire.call_count, 2)
        self.assertEqual(ensure.call_count, 2)

    def test_writer_binding_survives_reacquire_block(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        start = Mock(return_value=self.writer_result(self.target))
        first = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
            start_writer_fn=start,
        )
        second = work_acquire.acquire_work(
            params,
            acquire_resources_fn=Mock(side_effect=RuntimeError("resource conflict")),
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(),
            runner=Mock(),
            start_writer_fn=Mock(),
        )
        self.assertEqual(second["state"], "blocked")
        self.assertEqual(second["writer_job"], first["writer_job"])
        self.assertEqual(second["writer_start"]["state"], "started")
        self.assertTrue(second["replayed"])
        self.assertEqual(start.call_count, 1)

    def test_writer_preflight_failure_falls_back_to_controller(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        release = Mock()
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=self.acquire,
            release_resources_fn=release,
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                return_value={
                    "result_state": "CREATED",
                    "durable_receipt_sha256": "b" * 64,
                    "post_state": {
                        "target_registered": True,
                        "target_path_exists": True,
                    },
                }
            ),
            runner=Mock(),
            start_writer_fn=Mock(
                side_effect=work_acquire.ScopedWriterStartPreflight("bad command")
            ),
        )
        self.assertEqual(result["state"], "ready")
        self.assertEqual(result["next_action"], "controller_execute")
        self.assertEqual(result["writer_start"]["state"], "preflight_failed")
        release.assert_not_called()

    def test_unknown_writer_start_is_preserved_and_not_blindly_retried(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        release = Mock()
        acquire = Mock(side_effect=self.acquire)
        ensure = Mock(
            return_value={
                "result_state": "CREATED",
                "durable_receipt_sha256": "b" * 64,
                "post_state": {
                    "target_registered": True,
                    "target_path_exists": True,
                },
            }
        )
        start = Mock(side_effect=RuntimeError("lost writer launch response"))
        kwargs = {
            "acquire_resources_fn": acquire,
            "release_resources_fn": release,
            "inspect_resource_fn": Mock(),
            "ensure_worktree_fn": ensure,
            "runner": Mock(),
            "start_writer_fn": start,
        }
        first = work_acquire.acquire_work(params, **kwargs)
        second = work_acquire.acquire_work(params, **kwargs)
        self.assertEqual(first["state"], "outcome_unknown")
        self.assertEqual(
            first["next_action"], "readback_scoped_writer_before_retry"
        )
        self.assertTrue(second["replayed"])
        self.assertEqual(start.call_count, 1)
        self.assertEqual(acquire.call_count, 1)
        self.assertEqual(ensure.call_count, 1)
        release.assert_not_called()

    def test_writer_starting_crash_window_fails_closed_without_second_launch(self) -> None:
        params = self.parameters()
        params["scoped_writer_argv"] = ["writer", "--once"]
        params["scoped_writer_runtime_seconds"] = 600
        inputs = work_acquire._normalize(params)
        inputs.pop("_scoped_writer_argv")
        self.state.mkdir(mode=0o700)
        receipt_path = self.state / f"{inputs['lane_id']}.json"
        work_acquire._write_state(
            receipt_path,
            {
                "kind": work_acquire.LANE_KIND,
                "schema_version": work_acquire.SCHEMA_VERSION,
                "lane_id": inputs["lane_id"],
                "inputs_sha256": work_acquire._sha(inputs),
                "inputs": inputs,
                "attempt_count": 1,
                "created_at_unix": int(time.time()),
                "updated_at_unix": int(time.time()),
                "state": "writer_starting",
                "decision": "EXECUTE",
                "writer_start": {"state": "starting"},
                "next_action": "start_scoped_writer",
            },
        )
        acquire = Mock()
        ensure = Mock()
        start = Mock()
        result = work_acquire.acquire_work(
            params,
            acquire_resources_fn=acquire,
            release_resources_fn=Mock(),
            inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure,
            runner=Mock(),
            start_writer_fn=start,
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["decision"], "HARD_BLOCK")
        self.assertEqual(
            result["next_action"], "readback_scoped_writer_before_retry"
        )
        self.assertEqual(result["writer_start"]["state"], "outcome_unknown")
        self.assertTrue(result["replayed"])
        acquire.assert_not_called()
        ensure.assert_not_called()
        start.assert_not_called()

    def test_scoped_writer_argv_requires_scoped_writer_actor(self) -> None:
        params = self.parameters()
        params["scoped_writer_actor"] = None
        params["scoped_writer_argv"] = ["writer"]
        with self.assertRaisesRegex(ValueError, "requires scoped_writer_actor"):
            work_acquire.acquire_work(params)

    def test_identical_retry_reuses_lane_identity(self) -> None:
        ensure = Mock(return_value={
            "result_state": "ALREADY_CORRECT",
            "durable_receipt_sha256": "c" * 64,
            "post_state": {"target_registered": True, "target_path_exists": True},
        })
        params = self.parameters()
        first = work_acquire.acquire_work(
            params, acquire_resources_fn=self.acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=ensure, runner=Mock(),
        )
        second = work_acquire.acquire_work(
            params, acquire_resources_fn=self.acquire, release_resources_fn=Mock(),
            inspect_resource_fn=Mock(), ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(first["lane_id"], second["lane_id"])
        self.assertTrue(second["replayed"])
        self.assertEqual(second["attempt_count"], 2)

    def test_pre_effect_failure_releases_exact_acquired_leases(self) -> None:
        release = Mock(return_value={"released": True})
        ensure = Mock(return_value={
            "result_state": "NOT_ACCEPTED",
            "post_state": {"target_registered": False, "target_path_exists": False, "branch_ref_head": None},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["decision"], "AUTO_PREPARE_FAILED")
        release.assert_called_once()
        self.assertIsInstance(release.call_args.kwargs["expected_leases"], list)

    def test_preexisting_conflict_is_compensated(self) -> None:
        release = Mock(return_value={"released": True})
        ensure = Mock(return_value={
            "result_state": "CONFLICT",
            "post_state": {"target_registered": True, "target_path_exists": True, "branch_ref_head": SHA},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "blocked")
        self.assertFalse(result["mutation_attempted"])
        release.assert_called_once()

    def test_post_mutation_conflict_preserves_leases_for_reconciliation(self) -> None:
        release = Mock()
        ensure = Mock(return_value={
            "result_state": "CONFLICT",
            "mutation": {"returncode": 1},
            "post_state": {"target_registered": True, "target_path_exists": True, "branch_ref_head": SHA},
        })
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=ensure, runner=Mock(),
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["decision"], "HARD_BLOCK")
        release.assert_not_called()

    def test_exception_after_lease_acquisition_preserves_for_reconciliation(self) -> None:
        release = Mock()
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(side_effect=RuntimeError("lost response")), runner=Mock(),
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertIsNone(result["effect_observed"])
        release.assert_not_called()

    def test_preflight_exception_after_lease_acquisition_is_compensated(self) -> None:
        release = Mock(return_value={"released": True})
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(
                side_effect=work_acquire.worktree_ensure.WorktreeEnsurePreflight(
                    "invalid branch"
                )
            ),
            runner=Mock(),
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["decision"], "AUTO_PREPARE_FAILED")
        self.assertFalse(result["effect_observed"])
        release.assert_called_once()
        expected_leases = release.call_args.kwargs["expected_leases"]
        self.assertIsInstance(expected_leases, list)
        self.assertTrue(expected_leases)
        self.assertEqual(
            set(expected_leases[0]),
            work_acquire.resources.LEASE_SNAPSHOT_KEYS,
        )

    def test_non_object_result_is_durable_outcome_unknown(self) -> None:
        release = Mock()
        result = work_acquire.acquire_work(
            self.parameters(), acquire_resources_fn=self.acquire,
            release_resources_fn=release, inspect_resource_fn=Mock(),
            ensure_worktree_fn=Mock(return_value=None), runner=Mock(),
        )
        self.assertEqual(result["state"], "outcome_unknown")
        self.assertEqual(result["error_class"], "InvalidWorktreeEnsureResult")
        release.assert_not_called()


    def test_mcp_entry_binds_audit_to_runtime_base(self) -> None:
        params = self.parameters()
        expected = {"state": "ready", "decision": "EXECUTE"}
        with (
            patch.object(work_acquire.operator, "_require_operator_mutation"),
            patch.object(work_acquire.operator, "_require_operator_capability"),
            patch.object(work_acquire, "acquire_work", return_value=expected) as acquire,
        ):
            result = work_acquire.grabowski_work_acquire(
                source_kind=str(params["source_kind"]),
                source_id=str(params["source_id"]),
                controller_actor=str(params["controller_actor"]),
                repo=str(params["repo"]),
                base_head=str(params["base_head"]),
                branch=str(params["branch"]),
                target_path=str(params["target_path"]),
                purpose=str(params["purpose"]),
                retention_until_unix=int(params["retention_until_unix"]),
                idempotency_key=str(params["idempotency_key"]),
                resource_keys=[],
                system_convergence={
                    "change_risk": "R2",
                    "target_criticality": "essential",
                    "expected_protocol_head": "d" * 40,
                },
            )

        self.assertEqual(expected, result)
        self.assertEqual(
            acquire.call_args.args[0]["system_convergence"],
            {
                "change_risk": "R2",
                "target_criticality": "essential",
                "expected_protocol_head": "d" * 40,
            },
        )
        self.assertIs(
            acquire.call_args.kwargs["audit_fn"],
            work_acquire.operator.base._append_audit,
        )


if __name__ == "__main__":
    unittest.main()

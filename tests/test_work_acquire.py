from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock

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
            {"resource_key": key, "owner_id": owner, "expires_at_unix": int(time.time()) + 1200}
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
        ensure.assert_called_once()
        ensure_parameters = ensure.call_args.args[0]
        self.assertIs(ensure_parameters["reposkop_required"], True)

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


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

import grabowski_bureau_pickup as pickup


class BureauPickupLeaseCommitFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "BUR-RUN-20260914T120000Z-0123456789"
        self.intent = {
            "run_id": self.run_id,
            "task_id": "TEST-T084",
            "worker_id": "worker-test",
            "intent_sha256": "a" * 64,
            "lease_owner_id": f"bureau-run:{self.run_id}",
            "required_resource_keys": ["component:test-bureau-pickup"],
        }
        self.request = {
            "registry_root": "/tmp/test-registry",
            "coordination_root": "/tmp/test-coordination",
            "lease_ttl_seconds": 120,
            "nonconflict_proofs": {},
            "repository_scope_manifests": {},
            "create_workspace": False,
        }
        self.group = {
            "name": "other",
            "resource_keys": list(self.intent["required_resource_keys"]),
            "metadata": pickup._lease_metadata(self.intent, group="other"),
            "nonconflict_proof": None,
            "ttl_seconds": 120,
        }
        self.run_dir = Path("/tmp/test-pickup-run")

    def _lease_result(self) -> dict[str, object]:
        return {
            "owner_id": self.intent["lease_owner_id"],
            "leases": [
                {
                    "resource_key": self.intent["required_resource_keys"][0],
                    "owner_id": self.intent["lease_owner_id"],
                }
            ],
        }

    def test_initial_acquisition_commit_fence_allows_still_uncommitted_run(self) -> None:
        observed_precondition = None

        def acquire(*args, **kwargs):
            nonlocal observed_precondition
            observed_precondition = kwargs.get("_commit_precondition")
            self.assertTrue(callable(observed_precondition))
            observed_precondition()
            return self._lease_result()

        missing = {
            "status": "not-coordinated",
            "run": None,
            "code": "unknown-run",
        }
        with (
            mock.patch.object(pickup, "_acquisition_groups", return_value=[self.group]),
            mock.patch.object(pickup, "_coordination_status", return_value=missing),
            mock.patch.object(pickup.resources, "acquire_resources", side_effect=acquire),
            mock.patch.object(pickup, "_write_bound_json"),
        ):
            result = pickup._acquire_groups(self.intent, self.request, self.run_dir)

        self.assertTrue(callable(observed_precondition))
        self.assertEqual(self.run_id, result["run_id"])

    def test_waiting_acquisition_commit_fence_rejects_terminalized_run(self) -> None:
        terminal = {
            "status": "coordinated",
            "run": {
                "run_id": self.run_id,
                "task_id": self.intent["task_id"],
                "worker_id": self.intent["worker_id"],
                "state": "succeeded",
                "error": None,
            },
            "claim_intent_sha256": self.intent["intent_sha256"],
        }

        def acquire(*args, **kwargs):
            precondition = kwargs.get("_commit_precondition")
            self.assertTrue(callable(precondition))
            precondition()
            self.fail("terminal pickup authority reached the lease write")

        with (
            mock.patch.object(pickup, "_acquisition_groups", return_value=[self.group]),
            mock.patch.object(pickup, "_coordination_status", return_value=terminal),
            mock.patch.object(pickup.resources, "acquire_resources", side_effect=acquire),
            mock.patch.object(pickup, "_write_bound_json"),
        ):
            with self.assertRaises(pickup.BureauPickupError) as raised:
                pickup._acquire_groups(self.intent, self.request, self.run_dir)

        self.assertEqual("lease-acquisition-failed", raised.exception.code)
        cause = raised.exception.__cause__
        self.assertIsInstance(cause, pickup.BureauPickupError)
        self.assertEqual("pickup-lease-authority-terminal", cause.code)

    def test_waiting_acquisition_commit_fence_accepts_same_active_run(self) -> None:
        active = {
            "status": "coordinated",
            "run": {
                "run_id": self.run_id,
                "task_id": self.intent["task_id"],
                "worker_id": self.intent["worker_id"],
                "state": "running",
                "error": None,
            },
            "claim_intent_sha256": self.intent["intent_sha256"],
        }

        def acquire(*args, **kwargs):
            precondition = kwargs.get("_commit_precondition")
            self.assertTrue(callable(precondition))
            precondition()
            return self._lease_result()

        with (
            mock.patch.object(pickup, "_acquisition_groups", return_value=[self.group]),
            mock.patch.object(pickup, "_coordination_status", return_value=active),
            mock.patch.object(pickup.resources, "acquire_resources", side_effect=acquire),
            mock.patch.object(pickup, "_write_bound_json"),
        ):
            result = pickup._acquire_groups(self.intent, self.request, self.run_dir)

        self.assertEqual(self.run_id, result["run_id"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_bureau_pickup as pickup


class BureauPickupCommitFenceFindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "BUR-RUN-20260915T000000Z-0123456789"
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
        self.group = pickup._acquisition_groups(self.intent, self.request)[0]
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

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

    def test_initial_commit_fence_uses_frozen_registry_binding(self) -> None:
        binding = {"sentinel": "frozen-registry-binding"}
        missing = {"status": "not-coordinated", "run": None, "code": "unknown-run"}

        def bound_call(observed_binding, callback):
            self.assertIs(binding, observed_binding)
            return callback()

        def acquire(*args, **kwargs):
            precondition = kwargs.get("_commit_precondition")
            self.assertTrue(callable(precondition))
            precondition()
            return self._lease_result()

        with (
            mock.patch.object(pickup, "_coordination_status", return_value=missing),
            mock.patch.object(pickup, "_bound_bureau_call", side_effect=bound_call) as bound,
            mock.patch.object(pickup.resources, "acquire_resources", side_effect=acquire),
            mock.patch.object(pickup, "_write_bound_json"),
        ):
            result = pickup._acquire_groups(
                self.intent,
                self.request,
                self.run_dir,
                groups=[self.group],
                registry_binding=binding,
            )

        self.assertEqual(self.run_id, result["run_id"])
        bound.assert_called_once()

    def test_orphaned_expired_lease_cannot_rebind_before_resume(self) -> None:
        key = self.intent["required_resource_keys"][0]
        metadata_json, metadata_sha256 = pickup.resources._metadata(self.group["metadata"])
        purpose = f"Bureau coordinated pickup {self.run_id} group {self.group['name']}"
        original = {
            "resource_key": key,
            "owner_id": self.intent["lease_owner_id"],
            "purpose": purpose,
            "acquired_at_unix": 10,
            "updated_at_unix": 10,
            "expires_at_unix": 20,
            "metadata_sha256": metadata_sha256,
            "metadata_json": metadata_json,
        }
        acquisition = {
            "leases": [original],
            "acquisition_sha256": "b" * 64,
        }
        persisted = dict(original)

        with (
            mock.patch.object(pickup.resources, "_now", return_value=100),
            mock.patch.object(pickup.resources, "inspect_resource", return_value=None),
            mock.patch.object(pickup, "_persisted_resource_lease", return_value=persisted),
            mock.patch.object(pickup.resources, "rebind_same_owner_resources") as rebind,
            self.assertRaises(pickup.BureauPickupError) as raised,
        ):
            pickup._reacquire_orphaned_assignment_leases(
                self.intent,
                self.request,
                acquisition,
                self.run_dir,
                allow_expired_rebind=False,
            )

        self.assertEqual("orphan-recovery-lease-not-live-for-resume", raised.exception.code)
        rebind.assert_not_called()

    def test_active_resumed_run_can_enter_exact_lease_repair_mode(self) -> None:
        journal_identity = {
            "run_id": self.run_id,
            "task_id": self.intent["task_id"],
            "worker_id": self.intent["worker_id"],
            "task_sha256": "b" * 64,
            "plan_sha256": "c" * 64,
            "envelope_sha256": "d" * 64,
            "attempt": 2,
            "workspace_path": None,
            "workspace_branch": None,
        }
        run = {**journal_identity, "state": "assigned", "error": None}
        acquisition = {
            "run_id": self.run_id,
            "task_id": self.intent["task_id"],
            "owner_id": self.intent["lease_owner_id"],
            "claim_intent_sha256": self.intent["intent_sha256"],
            "resource_keys": self.intent["required_resource_keys"],
        }
        coordination = {
            "status": "coordinated",
            "run": run,
            "claim_intent_sha256": self.intent["intent_sha256"],
            "release": {
                "required": True,
                "owner_id": self.intent["lease_owner_id"],
                "resource_keys": self.intent["required_resource_keys"],
                "claim_intent_sha256": self.intent["intent_sha256"],
            },
            "blocking": True,
            "lease": {"status": "active-binding-drift"},
        }

        with mock.patch.object(pickup, "_require_active_execution_binding"):
            repaired = pickup._validate_resumed_run(
                coordination,
                self.intent,
                acquisition,
                journal_identity,
                allow_lease_repair=True,
            )
            with self.assertRaises(pickup.BureauPickupError) as raised:
                pickup._validate_resumed_run(
                    coordination,
                    self.intent,
                    acquisition,
                    journal_identity,
                )

        self.assertIs(run, repaired)
        self.assertEqual("claim-readback-blocking-or-incomplete", raised.exception.code)


if __name__ == "__main__":
    unittest.main()

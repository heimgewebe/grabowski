from pathlib import Path
import unittest
from unittest import mock

import grabowski_bureau_pickup as pickup


class BureauPickupLeaseCommitFenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.run_id = "BUR-RUN-20260915T000000Z-0123456789"
        self.intent = {
            "run_id": self.run_id, "task_id": "TEST-T084", "worker_id": "worker-test",
            "intent_sha256": "a" * 64, "lease_owner_id": f"bureau-run:{self.run_id}",
            "required_resource_keys": ["component:test-bureau-pickup"],
        }
        self.request = {
            "registry_root": "/tmp/test-registry", "coordination_root": "/tmp/test-coordination",
            "lease_ttl_seconds": 120, "nonconflict_proofs": {},
            "repository_scope_manifests": {}, "create_workspace": False,
        }
        self.group = pickup._acquisition_groups(self.intent, self.request)[0]
        self.run_dir = Path("/tmp/test-pickup-run")

    def _status(self, state: str) -> dict[str, object]:
        return {
            "status": "coordinated",
            "run": {
                "run_id": self.run_id, "task_id": self.intent["task_id"],
                "worker_id": self.intent["worker_id"], "state": state, "error": None,
            },
            "claim_intent_sha256": self.intent["intent_sha256"],
        }

    def _acquire(self, status: dict[str, object], binding=None):
        lease = {
            "owner_id": self.intent["lease_owner_id"],
            "leases": [{"resource_key": self.intent["required_resource_keys"][0],
                        "owner_id": self.intent["lease_owner_id"]}],
        }
        def acquire(*args, **kwargs):
            kwargs["_commit_precondition"]()
            return lease
        with (
            mock.patch.object(pickup, "_coordination_status", return_value=status),
            mock.patch.object(pickup, "_bound_bureau_call",
                              side_effect=lambda observed, callback: callback()) as bound,
            mock.patch.object(pickup.resources, "acquire_resources", side_effect=acquire),
            mock.patch.object(pickup, "_write_bound_json"),
        ):
            result = pickup._acquire_groups(
                self.intent, self.request, self.run_dir, groups=[self.group],
                registry_binding=binding,
            )
        return result, bound

    def test_initial_unknown_run_uses_frozen_registry_binding(self) -> None:
        binding = {"sentinel": "frozen"}
        missing = {"status": "not-coordinated", "run": None, "code": "unknown-run"}
        result, bound = self._acquire(missing, binding)
        self.assertEqual(self.run_id, result["run_id"])
        self.assertIs(binding, bound.call_args.args[0])

    def test_commit_fence_accepts_active_and_rejects_terminal_run(self) -> None:
        self.assertEqual(self.run_id, self._acquire(self._status("running"))[0]["run_id"])
        with self.assertRaises(pickup.BureauPickupError) as raised:
            self._acquire(self._status("succeeded"))
        self.assertEqual("pickup-lease-authority-terminal", raised.exception.__cause__.code)

    def test_orphaned_expired_lease_cannot_rebind_before_resume(self) -> None:
        key = self.intent["required_resource_keys"][0]
        metadata_json, metadata_sha256 = pickup.resources._metadata(self.group["metadata"])
        original = {
            "resource_key": key, "owner_id": self.intent["lease_owner_id"],
            "purpose": f"Bureau coordinated pickup {self.run_id} group {self.group['name']}",
            "acquired_at_unix": 10, "updated_at_unix": 10, "expires_at_unix": 20,
            "metadata_sha256": metadata_sha256, "metadata_json": metadata_json,
        }
        with (
            mock.patch.object(pickup.resources, "_now", return_value=100),
            mock.patch.object(pickup.resources, "inspect_resource", return_value=None),
            mock.patch.object(pickup, "_persisted_resource_lease", return_value=original),
            mock.patch.object(pickup.resources, "rebind_same_owner_resources") as rebind,
            self.assertRaises(pickup.BureauPickupError) as raised,
        ):
            pickup._reacquire_orphaned_assignment_leases(
                self.intent, self.request, {"leases": [original]}, self.run_dir,
                allow_expired_rebind=False,
            )
        self.assertEqual("orphan-recovery-lease-not-live-for-resume", raised.exception.code)
        rebind.assert_not_called()

    def test_active_resumed_run_repairs_only_explicit_lease_drift(self) -> None:
        journal = {
            "run_id": self.run_id, "task_id": self.intent["task_id"],
            "worker_id": self.intent["worker_id"], "task_sha256": "b" * 64,
            "plan_sha256": "c" * 64, "envelope_sha256": "d" * 64, "attempt": 2,
            "workspace_path": None, "workspace_branch": None,
        }
        run = {**journal, "state": "assigned", "error": None}
        acquisition = {
            "run_id": self.run_id, "task_id": self.intent["task_id"],
            "owner_id": self.intent["lease_owner_id"],
            "claim_intent_sha256": self.intent["intent_sha256"],
            "resource_keys": self.intent["required_resource_keys"],
        }
        coordination = {
            "status": "coordinated", "run": run,
            "claim_intent_sha256": self.intent["intent_sha256"], "blocking": True,
            "lease": {"status": "active-binding-drift"},
            "release": {
                "required": True, "owner_id": self.intent["lease_owner_id"],
                "resource_keys": self.intent["required_resource_keys"],
                "claim_intent_sha256": self.intent["intent_sha256"],
            },
        }
        with mock.patch.object(pickup, "_require_active_execution_binding"):
            repaired = pickup._validate_resumed_run(
                coordination, self.intent, acquisition, journal, allow_lease_repair=True)
            with self.assertRaises(pickup.BureauPickupError):
                pickup._validate_resumed_run(coordination, self.intent, acquisition, journal)
        self.assertIs(run, repaired)

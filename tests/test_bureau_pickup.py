from __future__ import annotations

import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import grabowski_bureau_pickup as pickup


class BureauPickupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.patches = [
            mock.patch.object(pickup, "STATE_ROOT", self.root / "state"),
            mock.patch.object(pickup.operator, "_require_operator_mutation"),
            mock.patch.object(pickup.bureau, "_audit"),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def request(self, **overrides):
        value = {
            "worker_id": "operator-test",
            "capabilities": ["repository", "shell"],
            "task_id": "TEST-T001",
            "base_dir": str(self.root / "worktrees"),
            "lease_ttl_seconds": 300,
            "create_workspace": True,
        }
        value.update(overrides)
        return value

    def intent(self, keys=None):
        run_id = "BUR-RUN-20260724T120000Z-0123456789"
        return {
            "schema_version": 1,
            "run_id": run_id,
            "task_id": "TEST-T001",
            "worker_id": "operator-test",
            "kind": "interactive-agent",
            "capabilities": ["repository", "shell"],
            "resource": None,
            "task_sha256": "1" * 64,
            "plan_sha256": "2" * 64,
            "required_resource_keys": sorted(keys or ["path:/tmp/pickup-test"]),
            "lease_owner_id": f"bureau-run:{run_id}",
            "created_at": "2026-07-24T12:00:00Z",
            "expires_at_unix": int(time.time()) + 300,
            "workspace": None,
            "operator_approval": {"approved": True},
            "runtime_truth_sha256": "3" * 64,
            "does_not_establish": [],
            "intent_sha256": "4" * 64,
        }

    @staticmethod
    def lease(key, owner, metadata="a" * 64):
        return {
            "resource_key": key,
            "owner_id": owner,
            "purpose": "test",
            "acquired_at_unix": 1,
            "updated_at_unix": 1,
            "expires_at_unix": int(time.time()) + 300,
            "metadata_sha256": metadata,
            "reclaimed_from_owner": None,
        }

    def test_execute_claims_after_exact_lease_acquisition(self) -> None:
        intent = self.intent()
        lease = self.lease(
            intent["required_resource_keys"][0], intent["lease_owner_id"]
        )
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "claimed", "run": {"run_id": intent["run_id"]}},
                ],
            ) as invoke,
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ) as acquire,
        ):
            result = pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(result["status"], "claimed")
        self.assertEqual(result["run_id"], intent["run_id"])
        self.assertEqual(acquire.call_count, 1)
        metadata = acquire.call_args.kwargs["metadata"]
        self.assertEqual(metadata["task_id"], intent["task_id"])
        self.assertEqual(metadata["run_id"], intent["run_id"])
        self.assertEqual(metadata["claim_intent_sha256"], intent["intent_sha256"])
        self.assertIn("--workspace", invoke.call_args_list[1].args[0])
        run_dir = Path(result["journal"])
        self.assertTrue((run_dir / "intent.json").is_file())
        self.assertTrue((run_dir / "acquisition.json").is_file())
        self.assertTrue((run_dir / "commit-result.json").is_file())
        self.assertEqual((run_dir / "intent.json").stat().st_mode & 0o777, 0o600)

    def test_repository_scope_is_required_before_any_acquisition(self) -> None:
        key = "repo:/tmp/repository"
        intent = self.intent([key])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value={"status": "claim-intent", "intent": intent},
            ),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(pickup.BureauPickupError, "repository-scope-required"):
                pickup.grabowski_bureau_pickup_execute(self.request())
        acquire.assert_not_called()

    def test_partial_acquisition_is_compensated(self) -> None:
        bureau_key = "/home/alex/repos/bureau/.bureau-scopes/core-code"
        repo_key = "repo:/tmp/repository"
        keys = [f"path:{bureau_key}", repo_key]
        intent = self.intent(keys)
        scope = {
            "schema_version": 1,
            "repository": "/tmp/repository",
            "task_id": intent["task_id"],
            "base_head": "a" * 40,
            "head": "a" * 40,
            "branch": "test-branch",
            "worktree": "/tmp/repository",
            "effects": ["write"],
            "paths": ["/tmp/repository"],
            "components": [],
            "runtime_resources": [],
            "processes": [],
            "deployments": [],
            "migrations": [],
            "generated_artifacts": [],
            "shared_gates": [],
        }
        first_lease = self.lease(keys[0], intent["lease_owner_id"])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value={"status": "claim-intent", "intent": intent},
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                side_effect=[
                    {"leases": [first_lease], "owner_id": intent["lease_owner_id"]},
                    RuntimeError("blocked"),
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": [first_lease]},
            ) as release,
        ):
            with self.assertRaisesRegex(pickup.BureauPickupError, "lease-acquisition-failed"):
                pickup.grabowski_bureau_pickup_execute(
                    self.request(repository_scope_manifests={repo_key: scope})
                )
        release.assert_called_once_with(intent["lease_owner_id"], [keys[0]])

    def test_current_group_snapshot_failure_compensates_current_acquisition(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        request = pickup._normalize_request(self.request())
        run_dir = pickup._run_directory(intent["run_id"])
        with (
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": []},
            ) as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "lease-acquisition-failed"
            ):
                pickup._acquire_groups(intent, request, run_dir)
        release.assert_called_once_with(intent["lease_owner_id"], [key])

    def test_current_group_journal_failure_compensates_current_acquisition(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        request = pickup._normalize_request(self.request())
        run_dir = pickup._run_directory(intent["run_id"])
        real_write = pickup._write_bound_json

        def fail_lease_journal(path, value):
            if path.name.startswith("lease-acquired-"):
                raise OSError("journal unavailable")
            return real_write(path, value)

        with (
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup, "_write_bound_json", side_effect=fail_lease_journal),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": [lease]},
            ) as release,
        ):
            with self.assertRaisesRegex(pickup.BureauPickupError, "lease-acquisition-failed"):
                pickup._acquire_groups(intent, request, run_dir)
        release.assert_called_once_with(intent["lease_owner_id"], [key])

    def test_ambiguous_commit_recovers_existing_run_without_release(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        coordinated = {
            "status": "coordinated",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "release": {"required": True},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {
                        "kind": "grabowski_bureau_intake_adapter_failure",
                        "code": "bureau-runtime-timeout",
                        "status": "unknown",
                        "ambiguity": True,
                    },
                    coordinated,
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            result = pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(result["status"], "recovered")
        release.assert_not_called()

    def test_definitive_missing_run_compensates_after_commit_failure(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "unknown", "code": "bureau-runtime-timeout"},
                    {"status": "error", "code": "unknown-run"},
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": [lease]},
            ) as release,
        ):
            result = pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(result["status"], "commit-not-applied")
        release.assert_called_once_with(intent["lease_owner_id"], [key])

    def create_acquisition_journal(self, intent, lease):
        run_dir = pickup._run_directory(intent["run_id"])
        value = {
            "schema_version": 1,
            "owner_id": intent["lease_owner_id"],
            "task_id": intent["task_id"],
            "run_id": intent["run_id"],
            "claim_intent_sha256": intent["intent_sha256"],
            "resource_keys": intent["required_resource_keys"],
            "leases": [lease],
            "groups": [],
        }
        value["acquisition_sha256"] = pickup._sha256(value)
        pickup._write_bound_json(run_dir / "acquisition.json", value)
        return run_dir, value

    def terminal_status(self, intent, state="failed"):
        return {
            "status": "coordinated",
            "run": {"run_id": intent["run_id"], "state": state},
            "release": {
                "required": True,
                "owner_id": intent["lease_owner_id"],
                "resource_keys": intent["required_resource_keys"],
                "claim_intent_sha256": intent["intent_sha256"],
            },
        }

    def test_release_requires_terminal_readback(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        self.create_acquisition_journal(intent, lease)
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value=self.terminal_status(intent, state="running"),
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(pickup.BureauPickupError, "run-still-active"):
                pickup.grabowski_bureau_pickup_release(intent["run_id"])
        release.assert_not_called()

    def test_terminal_release_checks_snapshot_and_releases_exact_keys(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        self.create_acquisition_journal(intent, lease)
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value=self.terminal_status(intent),
            ),
            mock.patch.object(
                pickup.resources,
                "inspect_resource",
                side_effect=[lease, None],
            ),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": [lease]},
            ) as release,
        ):
            result = pickup.grabowski_bureau_pickup_release(intent["run_id"])
        self.assertEqual(result["status"], "released")
        release.assert_called_once_with(intent["lease_owner_id"], [key])

    def test_release_rejects_metadata_drift(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        self.create_acquisition_journal(intent, lease)
        drifted = dict(lease)
        drifted["metadata_sha256"] = "b" * 64
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value=self.terminal_status(intent),
            ),
            mock.patch.object(
                pickup.resources, "inspect_resource", return_value=drifted
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "lease-release-metadata-drift"
            ):
                pickup.grabowski_bureau_pickup_release(intent["run_id"])
        release.assert_not_called()

    def test_release_rejects_acquisition_mode_drift(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _value = self.create_acquisition_journal(intent, lease)
        (run_dir / "acquisition.json").chmod(0o644)
        with mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke:
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "acquisition-mode-invalid"
            ):
                pickup.grabowski_bureau_pickup_release(intent["run_id"])
        invoke.assert_not_called()

    def test_release_rejects_hardlinked_acquisition_journal(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _value = self.create_acquisition_journal(intent, lease)
        (run_dir / "acquisition-link.json").hardlink_to(
            run_dir / "acquisition.json"
        )
        with mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke:
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "acquisition-hardlink-invalid"
            ):
                pickup.grabowski_bureau_pickup_release(intent["run_id"])
        invoke.assert_not_called()

    def test_release_rejects_tampered_acquisition_journal(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, value = self.create_acquisition_journal(intent, lease)
        value["task_id"] = "TAMPERED"
        (run_dir / "acquisition.json").write_text(
            json.dumps(value), encoding="utf-8"
        )
        with mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke:
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "acquisition-digest-mismatch"
            ):
                pickup.grabowski_bureau_pickup_release(intent["run_id"])
        invoke.assert_not_called()

    def test_lease_free_claim_omits_lease_binding(self) -> None:
        intent = self.intent([])
        intent["required_resource_keys"] = []
        with mock.patch.object(
            pickup.bureau,
            "_invoke_bureau",
            side_effect=[
                {"status": "claim-intent", "intent": intent},
                {"status": "claimed", "run": {"run_id": intent["run_id"]}},
            ],
        ) as invoke:
            result = pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(result["status"], "claimed")
        commit_argv = invoke.call_args_list[1].args[0]
        self.assertNotIn("--lease-binding", commit_argv)

    def test_bureau_effect_gate_ttl_is_capped_at_300_seconds(self) -> None:
        key = pickup.bureau_leases.BUREAU_WORKTREE_ADMIN_KEY
        intent = self.intent([key])
        lease = self.lease(key, intent["lease_owner_id"])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "claimed", "run": {"run_id": intent["run_id"]}},
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ) as acquire,
        ):
            pickup.grabowski_bureau_pickup_execute(
                self.request(lease_ttl_seconds=900)
            )
        self.assertEqual(acquire.call_args.kwargs["ttl_seconds"], 300)

    def test_commit_exception_uses_authoritative_readback(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        coordinated = {
            "status": "coordinated",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "release": {"required": True},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    RuntimeError("transport lost"),
                    coordinated,
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            result = pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(result["status"], "recovered")
        release.assert_not_called()

    def test_commit_and_readback_failure_retains_leases_as_recovery_required(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    RuntimeError("commit transport lost"),
                    RuntimeError("readback unavailable"),
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            result = pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(result["status"], "recovery-required")
        self.assertEqual(
            result["recovery"]["lease_owner_id"], intent["lease_owner_id"]
        )
        release.assert_not_called()

    def test_release_retry_is_idempotent_after_leases_are_absent(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _value = self.create_acquisition_journal(intent, lease)
        prior = {"owner_id": intent["lease_owner_id"], "released": [lease]}
        pickup._write_bound_json(run_dir / "release-result.json", prior)
        with (
            mock.patch.object(
                pickup.resources, "inspect_resource", return_value=None
            ) as inspect,
            mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke,
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            result = pickup.grabowski_bureau_pickup_release(intent["run_id"])
        self.assertEqual(result["status"], "already-released")
        self.assertEqual(inspect.call_count, 1)
        invoke.assert_not_called()
        release.assert_not_called()

    def test_exact_retry_recovers_own_existing_assignment_after_intent_expiry(self) -> None:
        request = self.request()
        normalized = pickup._normalize_request(request)
        intent = self.intent()
        intent["expires_at_unix"] = int(time.time()) - 60
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, acquisition = self.create_acquisition_journal(intent, lease)
        pickup._write_bound_json(run_dir / "request.json", normalized)
        pickup._write_bound_json(run_dir / "intent.json", intent)
        existing = {
            "status": "existing-assignment",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        coordinated = {
            "status": "coordinated",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[existing, coordinated],
            ),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            result = pickup.grabowski_bureau_pickup_execute(request)
        self.assertEqual(result["status"], "existing-assignment")
        self.assertEqual(
            result["acquisition_sha256"], acquisition["acquisition_sha256"]
        )
        acquire.assert_not_called()

    def test_existing_assignment_without_own_journal_fails_closed(self) -> None:
        intent = self.intent()
        existing = {
            "status": "existing-assignment",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        with (
            mock.patch.object(
                pickup.bureau, "_invoke_bureau", return_value=existing
            ),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(pickup.BureauPickupError, "request-missing"):
                pickup.grabowski_bureau_pickup_execute(self.request())
        acquire.assert_not_called()

    def test_status_does_not_create_private_state(self) -> None:
        intent = self.intent()
        self.assertFalse(pickup.STATE_ROOT.exists())
        with mock.patch.object(
            pickup.bureau,
            "_invoke_bureau",
            return_value={"status": "coordinated"},
        ):
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        self.assertFalse(result["journal_available"])
        self.assertFalse(pickup.STATE_ROOT.exists())

    def test_status_is_read_only_and_reports_journal_presence(self) -> None:
        intent = self.intent()
        pickup._run_directory(intent["run_id"])
        with mock.patch.object(
            pickup.bureau,
            "_invoke_bureau",
            return_value={"status": "coordinated"},
        ) as invoke:
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        self.assertTrue(result["journal_available"])
        self.assertIn("claim-coordination-status", invoke.call_args.args[0])


if __name__ == "__main__":
    unittest.main()

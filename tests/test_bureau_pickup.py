from __future__ import annotations

import ast
import asyncio
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import grabowski_bureau_pickup as pickup


REAL_CANONICAL_REGISTRY_BINDING = pickup._canonical_registry_binding
REAL_ASSERT_REGISTRY_BINDING = pickup._assert_registry_binding


class BureauPickupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry_root = self.root / "bureau"
        self.registry_root.mkdir()
        self.default_registry_binding = pickup._explicit_registry_binding(
            str(self.registry_root)
        )
        self.coordination_root = self.root / "bureau-state"
        self.patches = [
            mock.patch.object(pickup, "STATE_ROOT", self.root / "state"),
            mock.patch.object(
                pickup, "LEGACY_COORDINATION_ROOT", self.coordination_root
            ),
            mock.patch.object(pickup, "COORDINATION_ROOT", self.coordination_root),
            mock.patch.object(pickup.bureau, "BUREAU_ROOT", self.registry_root),
            mock.patch.object(
                pickup,
                "_canonical_registry_binding",
                return_value=self.default_registry_binding,
            ),
            mock.patch.object(pickup.operator, "_require_operator_mutation"),
            mock.patch.object(pickup.bureau, "_audit"),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def test_mcp_tool_registration_contract(self) -> None:
        tree = ast.parse(Path(pickup.__file__).read_text(encoding="utf-8"))
        expected = {
            "grabowski_bureau_pickup_execute": "MUTATING",
            "grabowski_bureau_pickup_status": "READ_ONLY",
            "grabowski_bureau_pickup_release": "MUTATING",
        }
        observed: dict[str, str] = {}
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not (
                    isinstance(decorator, ast.Call)
                    and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name)
                    and decorator.func.value.id == "mcp"
                    and decorator.func.attr == "tool"
                ):
                    continue
                values = {item.arg: item.value for item in decorator.keywords}
                name = values.get("name")
                annotations = values.get("annotations")
                if (
                    isinstance(name, ast.Constant)
                    and isinstance(name.value, str)
                    and isinstance(annotations, ast.Name)
                ):
                    observed[name.value] = annotations.id
        self.assertEqual(expected, observed)

    def test_execute_request_type_contract_is_complete_and_strict(self) -> None:
        required = {"worker_id", "capabilities", "task_id"}
        optional = {
            "resource",
            "kind",
            "base_dir",
            "approval_source",
            "lease_ttl_seconds",
            "create_workspace",
            "repository_scope_manifests",
            "nonconflict_proofs",
            "registry_root",
        }
        self.assertEqual(required, set(pickup.BureauPickupRequest.__required_keys__))
        self.assertEqual(optional, set(pickup.BureauPickupRequest.__optional_keys__))
        self.assertEqual(
            {"extra": "forbid", "strict": True},
            pickup.BureauPickupRequest.__pydantic_config__,
        )

    def test_execute_registered_request_schema_is_complete_and_strict(self) -> None:
        if not hasattr(pickup.mcp, "list_tools"):
            self.skipTest("real FastMCP unavailable in dependency-free validation")
        tool = next(
            item
            for item in asyncio.run(pickup.mcp.list_tools())
            if item.name == "grabowski_bureau_pickup_execute"
        )
        schema = tool.inputSchema
        self.assertEqual({"request"}, set(schema["properties"]))
        self.assertEqual(["request"], schema["required"])

        request_schema = schema
        for component in (
            schema["properties"]["request"]["$ref"].removeprefix("#/").split("/")
        ):
            request_schema = request_schema[component]

        required = {"worker_id", "capabilities", "task_id"}
        optional = {
            "resource",
            "kind",
            "base_dir",
            "approval_source",
            "lease_ttl_seconds",
            "create_workspace",
            "repository_scope_manifests",
            "nonconflict_proofs",
            "registry_root",
        }
        self.assertEqual("object", request_schema["type"])
        self.assertEqual(required | optional, set(request_schema["properties"]))
        self.assertEqual(required, set(request_schema["required"]))
        self.assertTrue(optional.isdisjoint(request_schema["required"]))
        self.assertFalse(request_schema["additionalProperties"])

    def test_minimal_valid_request_normalizes_without_changing_runtime_defaults(
        self,
    ) -> None:
        normalized = pickup._normalize_request(
            {
                "worker_id": "operator-test",
                "capabilities": ["shell", "repository"],
                "task_id": "TEST-T001",
            }
        )
        self.assertEqual("operator-test", normalized["worker_id"])
        self.assertEqual(["repository", "shell"], normalized["capabilities"])
        self.assertEqual("TEST-T001", normalized["task_id"])
        self.assertEqual("interactive-agent", normalized["kind"])
        self.assertEqual(900, normalized["lease_ttl_seconds"])
        self.assertTrue(normalized["create_workspace"])
        self.assertEqual(
            str(pickup.COORDINATION_ROOT),
            normalized["coordination_root"],
        )

    def test_normalizer_still_rejects_unknown_request_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported request fields"):
            pickup._normalize_request(
                {
                    "worker_id": "operator-test",
                    "capabilities": ["repository"],
                    "task_id": "TEST-T001",
                    "goal": "guessing must fail closed",
                }
            )

    def test_private_root_rejects_symlink(self) -> None:
        target = self.root / "redirected-root"
        target.mkdir(mode=0o700)
        pickup.STATE_ROOT.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "pickup-root-directory-open-failed"
        ):
            pickup._private_root()

    def test_run_directory_rejects_symlinked_runs_directory(self) -> None:
        pickup._private_root()
        target = self.root / "redirected-runs"
        target.mkdir(mode=0o700)
        (pickup.STATE_ROOT / "runs").symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "pickup-runs-directory-open-failed"
        ):
            pickup._run_directory(self.intent()["run_id"])

    def test_run_directory_rejects_symlinked_run_directory(self) -> None:
        pickup._private_root()
        runs = pickup.STATE_ROOT / "runs"
        runs.mkdir(mode=0o700)
        target = self.root / "redirected-run"
        target.mkdir(mode=0o700)
        (runs / self.intent()["run_id"]).symlink_to(
            target, target_is_directory=True
        )
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "pickup-run-directory-open-failed"
        ):
            pickup._run_directory(self.intent()["run_id"])

    def test_private_root_rejects_nonprivate_mode(self) -> None:
        pickup.STATE_ROOT.mkdir(mode=0o700)
        pickup.STATE_ROOT.chmod(0o755)
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "pickup-root-directory-unsafe"
        ):
            pickup._private_root()

    def test_private_root_rejects_foreign_owner_identity(self) -> None:
        pickup.STATE_ROOT.mkdir(mode=0o700)
        with mock.patch.object(pickup.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "pickup-root-directory-unsafe"
            ):
                pickup._private_root()

    def test_coordination_root_rejects_public_override(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported request fields"):
            pickup._normalize_request(
                self.request(coordination_root=str(self.root / "other-state"))
            )

    def test_coordination_root_rejects_registry_overlap(self) -> None:
        with mock.patch.object(pickup, "COORDINATION_ROOT", self.registry_root):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "coordination-root-overlaps-registry"
            ):
                pickup._normalize_request(self.request())

    def test_coordination_root_rejects_symlink(self) -> None:
        pickup._private_root()
        target = self.root / "redirected-coordination"
        target.mkdir(mode=0o700)
        pickup.COORDINATION_ROOT.symlink_to(
            target, target_is_directory=True
        )
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "pickup-coordination-open-failed"
        ):
            pickup._normalize_request(self.request())

    def test_coordination_root_rejects_nonprivate_mode(self) -> None:
        pickup._private_root()
        coordination = pickup.COORDINATION_ROOT
        coordination.mkdir(mode=0o700)
        coordination.chmod(0o755)
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "pickup-coordination-directory-unsafe"
        ):
            pickup._normalize_request(self.request())

    def test_coordination_root_is_created_private_and_stable(self) -> None:
        normalized = pickup._normalize_request(self.request())
        path = Path(pickup._ensure_coordination_root(normalized["coordination_root"]))
        self.assertEqual(pickup.COORDINATION_ROOT, path)
        self.assertEqual(0o700, path.stat().st_mode & 0o777)
        self.assertEqual(
            normalized["coordination_root"],
            pickup._ensure_coordination_root(normalized["coordination_root"]),
        )

    def test_concurrent_identical_artifact_winner_is_idempotent(self) -> None:
        run_dir = pickup._run_directory(self.intent()["run_id"])
        target = run_dir / "race.json"
        payload = {"ok": True}
        encoded = pickup._canonical_json(payload)
        real_open = os.open
        injected = False

        def publish_winner(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal injected
            if (
                path == target.name
                and flags & os.O_EXCL
                and dir_fd is not None
                and not injected
            ):
                injected = True
                winner = real_open(path, flags, mode, dir_fd=dir_fd)
                try:
                    os.write(winner, encoded)
                    os.fsync(winner)
                finally:
                    os.close(winner)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(pickup.os, "open", side_effect=publish_winner):
            digest = pickup._write_bound_json(target, payload)
        self.assertTrue(injected)
        self.assertEqual(digest, pickup.hashlib.sha256(encoded).hexdigest())
        self.assertEqual(target.read_bytes(), encoded)

    def test_artifact_publish_rejects_run_directory_path_swap(self) -> None:
        run_dir = pickup._run_directory(self.intent()["run_id"])
        real_assert = pickup._assert_private_directory_binding
        run_checks = 0

        def swap_on_publish(descriptor, path, *, label):
            nonlocal run_checks
            if label == "pickup-run":
                run_checks += 1
                if run_checks == 3:
                    displaced = path.with_name(path.name + "-displaced")
                    path.rename(displaced)
                    path.mkdir(mode=0o700)
            return real_assert(descriptor, path, label=label)

        with mock.patch.object(
            pickup,
            "_assert_private_directory_binding",
            side_effect=swap_on_publish,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "pickup-run-directory-unsafe"
            ):
                pickup._write_bound_json(run_dir / "artifact.json", {"ok": True})
        self.assertFalse((run_dir / "artifact.json").exists())
        self.assertFalse(
            (run_dir.with_name(run_dir.name + "-displaced") / "artifact.json").exists()
        )

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

    @staticmethod
    def coordinated_status(intent, state="assigned", blocking=False):
        keys = intent["required_resource_keys"]
        return {
            "status": "coordinated",
            "run": {
                "run_id": intent["run_id"],
                "task_id": intent["task_id"],
                "worker_id": intent["worker_id"],
                "state": state,
            },
            "claim_intent_sha256": intent["intent_sha256"],
            "release": {
                "required": bool(keys),
                "owner_id": intent["lease_owner_id"],
                "resource_keys": keys,
                "claim_intent_sha256": intent["intent_sha256"],
            },
            "blocking": blocking,
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
                    self.coordinated_status(intent),
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
        intent_argv = invoke.call_args_list[0].args[0]
        self.assertTrue(invoke.call_args_list[0].kwargs["include_runtime_identity"])
        commit_argv = invoke.call_args_list[1].args[0]
        readback_argv = invoke.call_args_list[2].args[0]
        expected_coordination = str(pickup.COORDINATION_ROOT)
        for argv in (intent_argv, commit_argv, readback_argv):
            root_index = argv.index("--root")
            self.assertEqual(argv[root_index + 1], str(self.registry_root))
            state_index = argv.index("--state-root")
            self.assertEqual(argv[state_index + 1], expected_coordination)
        self.assertIn("--workspace", commit_argv)
        self.assertEqual(0o700, Path(expected_coordination).stat().st_mode & 0o777)
        run_dir = Path(result["journal"])
        self.assertTrue((run_dir / "intent.json").is_file())
        self.assertEqual(
            self.default_registry_binding["identity"],
            json.loads(
                (run_dir / "registry-binding.json").read_text(encoding="utf-8")
            ),
        )
        self.assertEqual(
            self.default_registry_binding["identity"]["binding_sha256"],
            result["registry_binding_sha256"],
        )
        self.assertTrue((run_dir / "acquisition.json").is_file())
        self.assertTrue((run_dir / "commit-result.json").is_file())
        self.assertTrue((run_dir / "commit-readback.json").is_file())
        self.assertEqual(
            pickup._sha256(self.coordinated_status(intent)),
            result["run_readback_sha256"],
        )
        stored_request = json.loads((run_dir / "request.json").read_text(encoding="utf-8"))
        self.assertEqual(expected_coordination, stored_request["coordination_root"])
        self.assertEqual(
            self.default_registry_binding["identity"]["binding_sha256"],
            stored_request["registry_binding_sha256"],
        )
        self.assertEqual((run_dir / "intent.json").stat().st_mode & 0o777, 0o600)

    def managed_registry_fixture(self):
        source_commit = "a" * 40
        relative = "registry/queue.json"
        tracked = self.registry_root / relative
        tracked.parent.mkdir()
        tracked.write_text('{"queue":[]}\n', encoding="utf-8")
        paths = [relative]
        tree_sha256 = pickup._observed_registry_tree_sha256(
            self.registry_root, paths
        )
        inventory_path = self.registry_root / ".bureau-runtime-snapshot.json"
        inventory_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "bureau_registry_snapshot",
                    "source_commit": source_commit,
                    "tree_sha256": tree_sha256,
                    "paths": paths,
                }
            ),
            encoding="utf-8",
        )
        inventory = pickup.bureau._read_regular_file_snapshot(
            inventory_path, label="test-inventory"
        )
        managed = mock.Mock()
        managed.registry_root = self.registry_root
        managed.source_commit = source_commit
        managed.registry_tree_sha256 = tree_sha256
        managed.launcher.sha256 = "c" * 64
        managed.manifest.sha256 = "d" * 64
        managed.inventory = inventory
        return managed, tracked

    def canonical_registry_binding_fixture(self):
        managed, tracked = self.managed_registry_fixture()
        with (
            mock.patch.object(
                pickup.bureau, "_managed_runtime_binding", return_value=managed
            ),
            mock.patch.object(pickup.bureau, "_assert_managed_runtime_unchanged"),
        ):
            binding = REAL_CANONICAL_REGISTRY_BINDING()
        return binding, managed, tracked

    def test_canonical_binding_uses_managed_manifest_identity(self) -> None:
        managed, _tracked = self.managed_registry_fixture()
        with (
            mock.patch.object(
                pickup.bureau, "_managed_runtime_binding", return_value=managed
            ),
            mock.patch.object(
                pickup.bureau, "_assert_managed_runtime_unchanged"
            ) as assert_unchanged,
        ):
            binding = REAL_CANONICAL_REGISTRY_BINDING()
        self.assertEqual("canonical-registry-binding", binding["identity"]["kind"])
        self.assertEqual(str(self.registry_root), binding["identity"]["registry_root"])
        self.assertEqual(managed.source_commit, binding["identity"]["source_commit"])
        self.assertEqual(
            managed.registry_tree_sha256,
            binding["identity"]["registry_tree_sha256"],
        )
        self.assertEqual(
            managed.inventory.sha256, binding["identity"]["inventory_sha256"]
        )
        assert_unchanged.assert_called_once_with(managed)

    def test_journal_binding_keeps_deployment_digests_as_provenance(self) -> None:
        binding, managed, _tracked = self.canonical_registry_binding_fixture()
        with mock.patch.object(
            pickup.bureau,
            "_managed_runtime_binding",
            side_effect=AssertionError("journal replay must not read current deployment"),
        ):
            replayed = pickup._registry_binding_from_identity(binding["identity"])
        self.assertIsNone(replayed["managed_runtime"])
        self.assertEqual(
            managed.launcher.sha256, replayed["identity"]["launcher_sha256"]
        )
        self.assertEqual(
            managed.manifest.sha256, replayed["identity"]["manifest_sha256"]
        )

    def test_canonical_registry_tree_drift_fails_before_effect(self) -> None:
        managed, tracked = self.managed_registry_fixture()
        with (
            mock.patch.object(
                pickup.bureau, "_managed_runtime_binding", return_value=managed
            ),
            mock.patch.object(
                pickup.bureau, "_assert_managed_runtime_unchanged"
            ),
        ):
            binding = REAL_CANONICAL_REGISTRY_BINDING()
            tracked.write_text('{"queue":["drift"]}\n', encoding="utf-8")
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "canonical-registry-tree-drift"
            ):
                REAL_ASSERT_REGISTRY_BINDING(binding)

    def test_canonical_manifest_failure_has_stable_fail_closed_code(self) -> None:
        with mock.patch.object(
            pickup.bureau,
            "_managed_runtime_binding",
            side_effect=RuntimeError("deployment-manifest-invalid"),
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError,
                "canonical-registry-binding-unavailable",
            ):
                REAL_CANONICAL_REGISTRY_BINDING()

    def test_canonical_manifest_drift_has_stable_fail_closed_code(self) -> None:
        managed = object()
        binding = {
            "identity": self.default_registry_binding["identity"],
            "managed_runtime": managed,
            "explicit": False,
        }
        with mock.patch.object(
            pickup.bureau,
            "_assert_managed_runtime_unchanged",
            side_effect=RuntimeError("deployment-manifest-changed-during-call"),
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "canonical-registry-binding-drift"
            ):
                REAL_ASSERT_REGISTRY_BINDING(binding)

    def test_journal_registry_binding_rejects_digest_tamper(self) -> None:
        run_dir = pickup._run_directory(self.intent()["run_id"])
        tampered = dict(self.default_registry_binding["identity"])
        tampered["registry_root"] = str(self.root)
        pickup._write_bound_json(run_dir / "registry-binding.json", tampered)
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "registry-binding-digest-mismatch"
        ):
            pickup._read_journal_registry_binding(
                run_dir,
                str(self.registry_root),
                expected_sha256=None,
            )

    def test_binding_marker_without_binding_fails_closed(self) -> None:
        run_dir = pickup._run_directory(self.intent()["run_id"])
        request = pickup._normalize_request(self.request())
        pickup._write_bound_json(
            run_dir / "request.json",
            {
                **request,
                "registry_binding_sha256": self.default_registry_binding[
                    "identity"
                ]["binding_sha256"],
            },
        )
        with self.assertRaisesRegex(
            pickup.BureauPickupError, "registry-binding-missing"
        ):
            pickup._root_binding_for_run(self.intent()["run_id"])

    def test_default_root_ignores_dirty_conventional_checkout(self) -> None:
        dirty_checkout = self.root / "dirty-conventional-checkout"
        dirty_checkout.mkdir()
        intent = self.intent()
        with (
            mock.patch.object(pickup.bureau, "BUREAU_ROOT", dirty_checkout),
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value={"status": "claim-intent", "intent": intent},
            ) as invoke,
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                side_effect=RuntimeError("stop after root observation"),
            ),
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "lease-acquisition-failed"
            ):
                pickup.grabowski_bureau_pickup_execute(self.request())
        argv = invoke.call_args.args[0]
        self.assertEqual(
            str(self.registry_root), argv[argv.index("--root") + 1]
        )

    def test_explicit_registry_root_preserves_override(self) -> None:
        explicit = self.root / "explicit-registry"
        explicit.mkdir()
        normalized, binding = pickup._prepare_request(
            self.request(registry_root=str(explicit))
        )
        self.assertEqual(str(explicit), normalized["registry_root"])
        self.assertEqual("explicit-registry-root", binding["identity"]["kind"])

    def test_missing_canonical_manifest_fails_before_bureau_or_lease_effect(self) -> None:
        with (
            mock.patch.object(
                pickup,
                "_canonical_registry_binding",
                side_effect=pickup.BureauPickupError(
                    "canonical-registry-binding-unavailable"
                ),
            ),
            mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke,
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError,
                "canonical-registry-binding-unavailable",
            ):
                pickup.grabowski_bureau_pickup_execute(self.request())
        invoke.assert_not_called()
        acquire.assert_not_called()

    def test_canonical_snapshot_drift_after_intent_precedes_lease_effect(self) -> None:
        intent = self.intent()
        with (
            mock.patch.object(
                pickup,
                "_assert_registry_binding",
                side_effect=[
                    None,
                    pickup.BureauPickupError("canonical-registry-binding-drift"),
                ],
            ),
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value={"status": "claim-intent", "intent": intent},
            ) as invoke,
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "canonical-registry-binding-drift"
            ):
                pickup.grabowski_bureau_pickup_execute(self.request())
        invoke.assert_called_once()
        acquire.assert_not_called()

    def test_relative_registry_root_is_rejected_before_any_effect(self) -> None:
        with (
            mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke,
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(ValueError, "registry_root must be absolute"):
                pickup.grabowski_bureau_pickup_execute(
                    self.request(registry_root="relative/bureau")
                )
        invoke.assert_not_called()
        acquire.assert_not_called()

    def test_claim_intent_root_refusal_precedes_lease_acquisition(self) -> None:
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value={"status": "explicit-registry-root-required"},
            ) as invoke,
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError,
                "claim-intent-explicit-registry-root-required",
            ):
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(invoke.call_count, 1)
        acquire.assert_not_called()

    def test_claim_intent_rejection_exposes_structured_runtime_drift(self) -> None:
        payload = {
            "status": "no-eligible-task",
            "detail": json.dumps(
                {
                    "rejected": [
                        {
                            "task_id": "TEST-T001",
                            "reasons": ["state is verified"],
                        }
                    ]
                }
            ),
            "runtime_identity": {
                "compatibility": {
                    "status": "stale",
                    "reason_codes": ["release-registry-identity-mismatch"],
                    "mutation_allowed": False,
                },
                "registry": {
                    "root": "/tmp/bureau",
                    "head": "a" * 40,
                    "origin_main": "a" * 40,
                    "head_equals_origin_main": True,
                    "dirty": False,
                },
                "manifest": {
                    "source_commit": "b" * 40,
                    "canonical_registry": {"source_commit": "b" * 40},
                },
            },
        }
        with (
            mock.patch.object(pickup.bureau, "_invoke_bureau", return_value=payload),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-intent-no-eligible-task"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        details = raised.exception.details
        self.assertEqual(
            details["detail"]["rejected"][0]["reasons"], ["state is verified"]
        )
        self.assertEqual(
            details["runtime_identity"]["compatibility"]["reason_codes"],
            ["release-registry-identity-mismatch"],
        )
        self.assertEqual(
            details["runtime_identity"]["manifest"]["source_commit"], "b" * 40
        )
        acquire.assert_not_called()

    def test_claim_intent_approval_rejection_preserves_required_level(self) -> None:
        payload = {
            "schema_version": 1,
            "kind": "bureau_approval_required",
            "status": "approval-required",
            "code": "approval-required",
            "approval": {
                "action_class": "runtime_mutation",
                "action_classes": ["runtime_mutation"],
                "required": True,
                "required_level": "break_glass",
                "allowed": False,
                "reason": (
                    "approval level operator is not accepted for required break_glass"
                ),
                "evidence": {
                    "schema_version": 1,
                    "approved": True,
                    "level": "operator",
                    "scope": ["runtime_mutation"],
                },
            },
            "effect_started": False,
            "retryable": False,
            "ambiguity": False,
            "required_readback": [],
        }
        with (
            mock.patch.object(pickup.bureau, "_invoke_bureau", return_value=payload),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-intent-approval-required"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())

        approval = raised.exception.details["approval"]
        self.assertEqual(approval["action_classes"], ["runtime_mutation"])
        self.assertEqual(approval["required_level"], "break_glass")
        self.assertEqual(approval["evidence"]["level"], "operator")
        acquire.assert_not_called()


    def test_claim_intent_adapter_failure_preserves_retry_contract(self) -> None:
        for code, retryable in (
            ("bureau-runtime-timeout", True),
            ("bureau-runtime-drift", False),
        ):
            with self.subTest(code=code):
                payload = {
                    "schema_version": 1,
                    "kind": "grabowski_bureau_intake_adapter_failure",
                    "code": code,
                    "effect_started": False,
                    "retryable": retryable,
                    "ambiguity": False,
                    "required_readback": [],
                    "details": {"error_type": "RuntimeError"},
                }
                with (
                    mock.patch.object(
                        pickup.bureau, "_invoke_bureau", return_value=payload
                    ),
                    mock.patch.object(
                        pickup.resources, "acquire_resources"
                    ) as acquire,
                ):
                    with self.assertRaisesRegex(
                        pickup.BureauPickupError, f"claim-intent-{code}"
                    ) as raised:
                        pickup.grabowski_bureau_pickup_execute(self.request())
                self.assertEqual(
                    raised.exception.details["adapter_failure"],
                    {
                        "schema_version": 1,
                        "effect_started": False,
                        "retryable": retryable,
                        "ambiguity": False,
                        "required_readback": [],
                        "details": {"error_type": "RuntimeError"},
                    },
                )
                acquire.assert_not_called()

    def test_claim_intent_rejection_bounds_oversized_values(self) -> None:
        oversized = "x" * (pickup.MAX_CLAIM_REJECTION_VALUE_BYTES + 1)
        rejection = pickup._claim_intent_rejection(
            {
                "status": "no-eligible-task",
                "code": oversized,
                "detail": oversized,
                "kind": "grabowski_bureau_intake_adapter_failure",
                "details": {"message": oversized},
            }
        )

        self.assertEqual(rejection.code, "claim-intent-not-ready")
        for key in ("source_code", "detail", "adapter_failure"):
            summary = rejection.details[key]
            self.assertTrue(summary["raw_omitted"])
            self.assertGreater(
                summary["size_bytes"], pickup.MAX_CLAIM_REJECTION_VALUE_BYTES
            )
            self.assertRegex(summary["sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(oversized, json.dumps(rejection.details))

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
        coordinated = self.coordinated_status(intent)
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

    def test_pre_effect_commit_refusal_compensates_and_raises(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {
                        "status": "explicit-registry-root-required",
                        "effect_started": False,
                        "ambiguity": False,
                    },
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
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-not-applied"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(
            raised.exception.details["result"]["status"], "commit-not-applied"
        )
        release.assert_called_once_with(intent["lease_owner_id"], [key])

    def test_coordinated_readback_text_cannot_trigger_missing_run_compensation(
        self,
    ) -> None:
        intent = self.intent()
        intent["worker_id"] = "agent unknown run"
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        coordinated = self.coordinated_status(intent)
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "claimed", "run": {"run_id": intent["run_id"]}},
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
            result = pickup.grabowski_bureau_pickup_execute(
                self.request(worker_id=intent["worker_id"])
            )
        self.assertEqual("claimed", result["status"])
        self.assertEqual(
            pickup._sha256(coordinated), result["run_readback_sha256"]
        )
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
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-not-applied"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(
            raised.exception.details["result"]["status"], "commit-not-applied"
        )
        release.assert_called_once_with(intent["lease_owner_id"], [key])

    def test_unknown_run_code_with_run_evidence_retains_leases(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        contradictory = {
            "status": "error",
            "code": "unknown-run",
            "run": {"run_id": intent["run_id"]},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "unknown", "code": "bureau-runtime-timeout"},
                    contradictory,
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-recovery-required"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(
            "recovery-required", raised.exception.details["result"]["status"]
        )
        release.assert_not_called()

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

    def write_registry_bound_request(self, run_dir, request, binding=None):
        selected = binding or self.default_registry_binding
        pickup._write_bound_json(
            run_dir / "registry-binding.json",
            selected["identity"],
        )
        bound_request = {
            **request,
            "registry_binding_sha256": selected["identity"]["binding_sha256"],
        }
        pickup._write_bound_json(run_dir / "request.json", bound_request)
        return bound_request

    def terminal_status(self, intent, state="failed"):
        return self.coordinated_status(intent, state=state)

    def test_journal_bound_release_rejects_registry_tree_drift(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _acquisition = self.create_acquisition_journal(intent, lease)
        binding, _managed, tracked = self.canonical_registry_binding_fixture()
        request = pickup._normalize_request(
            self.request(registry_root=str(self.registry_root))
        )
        self.write_registry_bound_request(run_dir, request, binding)
        tracked.write_text('{"queue":["drift"]}\n', encoding="utf-8")
        with (
            mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke,
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "canonical-registry-tree-drift"
            ):
                pickup.grabowski_bureau_pickup_release(intent["run_id"])
        invoke.assert_not_called()
        release.assert_not_called()

    def test_release_uses_journal_bound_coordination_root(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _acquisition = self.create_acquisition_journal(intent, lease)
        request = pickup._normalize_request(self.request())
        self.write_registry_bound_request(run_dir, request)
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value=self.terminal_status(intent),
            ) as invoke,
            mock.patch.object(
                pickup.resources, "inspect_resource", side_effect=[lease, None]
            ),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": [lease]},
            ),
        ):
            result = pickup.grabowski_bureau_pickup_release(intent["run_id"])
        argv = invoke.call_args.args[0]
        self.assertEqual(
            request["coordination_root"], argv[argv.index("--state-root") + 1]
        )
        self.assertEqual("journal-bound", result["root_binding_source"])

    def test_legacy_release_uses_implicit_state_and_gates_legacy_path(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _acquisition = self.create_acquisition_journal(intent, lease)
        legacy_request = pickup._normalize_request(self.request())
        legacy_request.pop("coordination_root")
        pickup._write_bound_json(run_dir / "request.json", legacy_request)
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value=self.terminal_status(intent),
            ) as invoke,
            mock.patch.object(
                pickup.resources, "inspect_resource", side_effect=[lease, None]
            ),
            mock.patch.object(
                pickup.resources,
                "release_resources",
                return_value={"released": [lease]},
            ),
        ):
            result = pickup.grabowski_bureau_pickup_release(intent["run_id"])
        self.assertNotIn("--state-root", invoke.call_args.args[0])
        self.assertEqual("legacy-journal-implicit-state", result["root_binding_source"])
        pickup.operator._require_operator_mutation.assert_any_call(
            "terminal_execute", path=str(pickup.LEGACY_COORDINATION_ROOT)
        )

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
                self.coordinated_status(intent),
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
                    self.coordinated_status(intent),
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
        coordinated = self.coordinated_status(intent)
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

    def test_successful_commit_without_authoritative_readback_retains_leases(
        self,
    ) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "claimed", "run": {"run_id": intent["run_id"]}},
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
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-recovery-required"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(
            "recovery-required", raised.exception.details["result"]["status"]
        )
        release.assert_not_called()

    def test_successful_commit_rejects_mismatched_run_readback(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        mismatched = self.coordinated_status(intent)
        mismatched["run"] = {**mismatched["run"], "task_id": "OTHER-TASK"}
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "claimed", "run": {"run_id": intent["run_id"]}},
                    mismatched,
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-recovery-required"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(
            "claim-readback-run-binding-mismatch",
            raised.exception.details["result"]["recovery"]["readback_error_code"],
        )
        release.assert_not_called()

    def test_claim_readback_rejects_each_authoritative_binding_drift(self) -> None:
        intent = self.intent()
        acquisition = {
            "run_id": intent["run_id"],
            "task_id": intent["task_id"],
            "owner_id": intent["lease_owner_id"],
            "claim_intent_sha256": intent["intent_sha256"],
            "resource_keys": intent["required_resource_keys"],
        }
        cases = [
            (
                "run",
                {"run": {"run_id": "BUR-RUN-20260724T000000Z-ffffffffff"}},
                "claim-readback-run-binding-mismatch",
            ),
            (
                "task",
                {"run": {"task_id": "OTHER-TASK"}},
                "claim-readback-run-binding-mismatch",
            ),
            (
                "worker",
                {"run": {"worker_id": "other-worker"}},
                "claim-readback-run-binding-mismatch",
            ),
            (
                "intent",
                {"claim_intent_sha256": "9" * 64},
                "claim-readback-intent-mismatch",
            ),
            (
                "release-owner",
                {"release": {"owner_id": "bureau-run:other"}},
                "claim-readback-release-binding-mismatch",
            ),
            (
                "release-resources",
                {"release": {"resource_keys": []}},
                "claim-readback-release-binding-mismatch",
            ),
            (
                "release-intent",
                {"release": {"claim_intent_sha256": "9" * 64}},
                "claim-readback-release-binding-mismatch",
            ),
            (
                "blocking",
                {"blocking": True},
                "claim-readback-blocking-or-incomplete",
            ),
        ]
        for label, changes, expected in cases:
            with self.subTest(binding=label):
                status = self.coordinated_status(intent)
                for key, value in changes.items():
                    status[key] = (
                        {**status[key], **value}
                        if isinstance(value, dict) and isinstance(status.get(key), dict)
                        else value
                    )
                with self.assertRaisesRegex(pickup.BureauPickupError, expected):
                    pickup._validate_claim_readback(status, intent, acquisition)

    def test_successful_commit_rejects_non_boolean_release_requirement(self) -> None:
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        malformed = self.coordinated_status(intent)
        malformed["release"] = {**malformed["release"], "required": 1}
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "claim-intent", "intent": intent},
                    {"status": "claimed", "run": {"run_id": intent["run_id"]}},
                    malformed,
                ],
            ),
            mock.patch.object(
                pickup.resources,
                "acquire_resources",
                return_value={"leases": [lease], "owner_id": intent["lease_owner_id"]},
            ),
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-recovery-required"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        self.assertEqual(
            "claim-readback-release-binding-mismatch",
            raised.exception.details["result"]["recovery"]["readback_error_code"],
        )
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
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "claim-commit-recovery-required"
            ) as raised:
                pickup.grabowski_bureau_pickup_execute(self.request())
        result = raised.exception.details["result"]
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
        coordinated = self.coordinated_status(intent)
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

    def test_existing_assignment_rejects_self_consistent_misbound_acquisition(
        self,
    ) -> None:
        request = self.request()
        normalized = pickup._normalize_request(request)
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, acquisition = self.create_acquisition_journal(intent, lease)
        acquisition["task_id"] = "OTHER-TASK"
        acquisition.pop("acquisition_sha256")
        acquisition["acquisition_sha256"] = pickup._sha256(acquisition)
        (run_dir / "acquisition.json").write_text(
            json.dumps(acquisition), encoding="utf-8"
        )
        pickup._write_bound_json(run_dir / "request.json", normalized)
        pickup._write_bound_json(run_dir / "intent.json", intent)
        existing = {
            "status": "existing-assignment",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[existing, self.coordinated_status(intent)],
            ),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError,
                "claim-readback-acquisition-binding-mismatch",
            ):
                pickup.grabowski_bureau_pickup_execute(request)
        acquire.assert_not_called()
        release.assert_not_called()

    def test_existing_terminal_assignment_accepts_bound_terminal_readback(self) -> None:
        request = self.request()
        normalized = pickup._normalize_request(request)
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, acquisition = self.create_acquisition_journal(intent, lease)
        pickup._write_bound_json(run_dir / "request.json", normalized)
        pickup._write_bound_json(run_dir / "intent.json", intent)
        existing = {
            "status": "existing-terminal",
            "run": {"run_id": intent["run_id"], "state": "failed"},
            "envelope": {"claim_intent": intent},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[existing, self.coordinated_status(intent, state="failed")],
            ),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            result = pickup.grabowski_bureau_pickup_execute(request)
        self.assertEqual("existing-terminal", result["status"])
        self.assertEqual(
            acquisition["acquisition_sha256"], result["acquisition_sha256"]
        )
        acquire.assert_not_called()
        release.assert_not_called()

    def test_existing_assignment_with_blocking_drift_retains_leases(self) -> None:
        request = self.request()
        normalized = pickup._normalize_request(request)
        intent = self.intent()
        key = intent["required_resource_keys"][0]
        lease = self.lease(key, intent["lease_owner_id"])
        run_dir, _acquisition = self.create_acquisition_journal(intent, lease)
        pickup._write_bound_json(run_dir / "request.json", normalized)
        pickup._write_bound_json(run_dir / "intent.json", intent)
        existing = {
            "status": "existing-assignment",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        with (
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    existing,
                    self.coordinated_status(intent, blocking=True),
                ],
            ),
            mock.patch.object(pickup.resources, "acquire_resources") as acquire,
            mock.patch.object(pickup.resources, "release_resources") as release,
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError,
                "claim-readback-blocking-or-incomplete",
            ):
                pickup.grabowski_bureau_pickup_execute(request)
        acquire.assert_not_called()
        release.assert_not_called()

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

    def test_legacy_existing_assignment_retry_uses_same_default_state(self) -> None:
        request = self.request()
        intent = self.intent()
        run_dir = pickup._run_directory(intent["run_id"])
        legacy_request = pickup._normalize_request(request)
        legacy_request.pop("coordination_root")
        pickup._write_bound_json(run_dir / "request.json", legacy_request)
        pickup._write_bound_json(run_dir / "intent.json", intent)
        _run_dir, acquisition = self.create_acquisition_journal(
            intent, self.lease(intent["required_resource_keys"][0], intent["lease_owner_id"])
        )
        existing = {
            "status": "existing-assignment",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        coordinated = self.coordinated_status(intent)
        with mock.patch.object(
            pickup.bureau, "_invoke_bureau", side_effect=[existing, coordinated]
        ):
            result = pickup.grabowski_bureau_pickup_execute(request)
        self.assertEqual("existing-assignment", result["status"])
        self.assertEqual(
            acquisition["acquisition_sha256"], result["acquisition_sha256"]
        )

    def test_legacy_existing_assignment_retry_fails_after_configured_cutover(
        self,
    ) -> None:
        request = self.request()
        intent = self.intent()
        run_dir = pickup._run_directory(intent["run_id"])
        legacy_request = pickup._normalize_request(request)
        legacy_request.pop("coordination_root")
        pickup._write_bound_json(run_dir / "request.json", legacy_request)
        pickup._write_bound_json(run_dir / "intent.json", intent)
        self.create_acquisition_journal(
            intent, self.lease(intent["required_resource_keys"][0], intent["lease_owner_id"])
        )
        existing = {
            "status": "existing-assignment",
            "run": {"run_id": intent["run_id"], "state": "assigned"},
            "envelope": {"claim_intent": intent},
        }
        with (
            mock.patch.object(
                pickup, "COORDINATION_ROOT", self.root / "custom-state"
            ),
            mock.patch.object(pickup.bureau, "_invoke_bureau", return_value=existing),
        ):
            with self.assertRaisesRegex(
                pickup.BureauPickupError,
                "legacy-assignment-retry-requires-status",
            ):
                pickup.grabowski_bureau_pickup_execute(request)

    def test_status_uses_journal_bound_coordination_root(self) -> None:
        intent = self.intent()
        normalized = pickup._normalize_request(self.request())
        run_dir = pickup._run_directory(intent["run_id"])
        self.write_registry_bound_request(run_dir, normalized)
        with mock.patch.object(
            pickup.bureau,
            "_invoke_bureau",
            return_value={"status": "coordinated"},
        ) as invoke:
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        argv = invoke.call_args.args[0]
        self.assertEqual(
            normalized["coordination_root"], argv[argv.index("--state-root") + 1]
        )
        self.assertEqual("journal-bound", result["root_binding_source"])
        self.assertEqual(normalized["coordination_root"], result["coordination_root"])

    def test_journal_bound_status_rejects_registry_tree_drift(self) -> None:
        intent = self.intent()
        managed, tracked = self.managed_registry_fixture()
        with (
            mock.patch.object(
                pickup.bureau, "_managed_runtime_binding", return_value=managed
            ),
            mock.patch.object(pickup.bureau, "_assert_managed_runtime_unchanged"),
        ):
            binding = REAL_CANONICAL_REGISTRY_BINDING()
        request = pickup._normalize_request(
            self.request(registry_root=str(self.registry_root))
        )
        run_dir = pickup._run_directory(intent["run_id"])
        self.write_registry_bound_request(run_dir, request, binding)
        tracked.write_text('{"queue":["drift"]}\n', encoding="utf-8")
        with mock.patch.object(pickup.bureau, "_invoke_bureau") as invoke:
            with self.assertRaisesRegex(
                pickup.BureauPickupError, "canonical-registry-tree-drift"
            ):
                pickup.grabowski_bureau_pickup_status(intent["run_id"])
        invoke.assert_not_called()

    def test_journal_bound_status_survives_configured_root_change(self) -> None:
        intent = self.intent()
        request = pickup._normalize_request(self.request())
        run_dir = pickup._run_directory(intent["run_id"])
        self.write_registry_bound_request(run_dir, request)
        with (
            mock.patch.object(
                pickup, "COORDINATION_ROOT", self.root / "new-configured-state"
            ),
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                return_value={"status": "coordinated"},
            ) as invoke,
        ):
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        argv = invoke.call_args.args[0]
        self.assertEqual(
            request["coordination_root"], argv[argv.index("--state-root") + 1]
        )
        self.assertEqual("journal-bound", result["root_binding_source"])
        self.assertEqual(request["coordination_root"], result["coordination_root"])

    def test_legacy_journal_status_uses_implicit_bureau_state(self) -> None:
        intent = self.intent()
        legacy_request = pickup._normalize_request(self.request())
        legacy_request.pop("coordination_root")
        run_dir = pickup._run_directory(intent["run_id"])
        pickup._write_bound_json(run_dir / "request.json", legacy_request)
        with mock.patch.object(
            pickup.bureau,
            "_invoke_bureau",
            return_value={"status": "coordinated"},
        ) as invoke:
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        self.assertNotIn("--state-root", invoke.call_args.args[0])
        self.assertIsNone(result["coordination_root"])
        self.assertEqual("legacy-journal-implicit-state", result["root_binding_source"])

    def test_status_without_journal_falls_back_only_after_unknown_run(self) -> None:
        intent = self.intent()
        with (
            mock.patch.object(
                pickup, "COORDINATION_ROOT", self.root / "custom-state"
            ),
            mock.patch.object(
                pickup.bureau,
                "_invoke_bureau",
                side_effect=[
                    {"status": "error", "code": "unknown-run"},
                    {
                        "status": "coordinated",
                        "run": {"run_id": intent["run_id"]},
                    },
                ],
            ) as invoke,
        ):
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        self.assertEqual(2, invoke.call_count)
        self.assertIn("--state-root", invoke.call_args_list[0].args[0])
        self.assertNotIn("--state-root", invoke.call_args_list[1].args[0])
        self.assertEqual("legacy-implicit-fallback", result["root_binding_source"])
        self.assertIsNone(result["coordination_root"])
        self.assertFalse(pickup.STATE_ROOT.exists())

    def test_status_without_journal_does_not_fallback_on_transport_error(self) -> None:
        intent = self.intent()
        failure = {
            "kind": "grabowski_bureau_intake_adapter_failure",
            "code": "bureau-runtime-timeout",
            "status": "unknown",
        }
        with (
            mock.patch.object(
                pickup, "COORDINATION_ROOT", self.root / "custom-state"
            ),
            mock.patch.object(
                pickup.bureau, "_invoke_bureau", return_value=failure
            ) as invoke,
        ):
            result = pickup.grabowski_bureau_pickup_status(intent["run_id"])
        self.assertEqual(1, invoke.call_count)
        self.assertEqual(failure, result["coordination"])
        self.assertEqual(
            "current-canonical-with-legacy-fallback", result["root_binding_source"]
        )

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
        self.assertEqual(
            str(pickup.COORDINATION_ROOT), result["coordination_root"]
        )
        self.assertEqual("current-canonical", result["root_binding_source"])
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

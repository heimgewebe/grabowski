from __future__ import annotations

import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import grabowski_bureau_intake as intake


class BureauIntakeAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.artifacts = self.root / "artifacts"
        self.patches = [
            mock.patch.object(intake, "ARTIFACT_ROOT", self.artifacts),
            mock.patch.object(intake.operator, "_require_operator_mutation"),
            mock.patch.object(intake, "_audit"),
            mock.patch.object(intake.base, "_append_audit"),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp.cleanup()

    def test_mutating_runtime_timeout_is_ambiguous_and_requires_readback(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = {"launcher_path": Path("/runtime/bureau")}
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ),
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged"),
            mock.patch.object(
                intake.bureau_runtime, "_safe_environment", return_value={}
            ),
            mock.patch.object(
                intake.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["bureau"], 30),
            ),
        ):
            result = intake._invoke_bureau(
                ["operator-task-publish"],
                mutation=True,
                required_readback=["pull_request", "resource_leases"],
            )
        self.assertEqual(result["code"], "bureau-runtime-timeout")
        self.assertTrue(result["effect_started"])
        self.assertTrue(result["ambiguity"])
        self.assertFalse(result["retryable"])
        self.assertEqual(
            result["required_readback"], ["pull_request", "resource_leases"]
        )

    def test_read_runtime_timeout_is_retryable_without_effect_claim(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = {"launcher_path": Path("/runtime/bureau")}
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ),
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged"),
            mock.patch.object(
                intake.bureau_runtime, "_safe_environment", return_value={}
            ),
            mock.patch.object(
                intake.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired(["bureau"], 30),
            ),
        ):
            result = intake._invoke_bureau(["operator-candidate-assess"])
        self.assertFalse(result["effect_started"])
        self.assertFalse(result["ambiguity"])
        self.assertTrue(result["retryable"])

    def test_invoke_uses_hash_bound_managed_launcher(self) -> None:
        runtime = {"python_launcher": Path("/runtime/python")}
        binding = {"launcher_path": Path("/runtime/managed-bureau")}
        completed = subprocess.CompletedProcess(
            ["bureau"],
            0,
            json.dumps(
                {
                    "schema_version": 1,
                    "result": {
                        "kind": "bureau_candidate_assessment",
                        "status": "ready",
                    },
                }
            ),
            "",
        )
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
            mock.patch.object(
                intake.bureau_runtime, "_assert_contract_runtime_unchanged"
            ) as contract_readback,
            mock.patch.object(intake, "_managed_runtime_binding", return_value=binding),
            mock.patch.object(intake, "_assert_managed_runtime_unchanged") as readback,
            mock.patch.object(
                intake.bureau_runtime,
                "_safe_environment",
                return_value={"PATH": "/usr/bin:/bin"},
            ),
            mock.patch.object(intake.subprocess, "run", return_value=completed) as run,
        ):
            result = intake._invoke_bureau(
                ["--json", "--json-envelope", "operator-candidate-assess"]
            )
        self.assertEqual(result["status"], "ready")
        self.assertEqual(
            run.call_args.args[0],
            [
                "/runtime/python",
                "-I",
                "/runtime/managed-bureau",
                "--json",
                "--json-envelope",
                "operator-candidate-assess",
            ],
        )
        self.assertEqual(
            run.call_args.kwargs["cwd"], intake.bureau_runtime.BUREAU_RUNTIME_ROOT
        )
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin"})
        contract_readback.assert_called_once_with(runtime)
        readback.assert_called_once_with(binding)

    def _managed_runtime_fixture(self) -> tuple[Path, Path, Path, str, str]:
        runtime_root = self.root / "bureau-runtime"
        snapshots_root = runtime_root / "registry-snapshots"
        registry_root = snapshots_root / "snapshot-a"
        registry_root.mkdir(parents=True)
        source_commit = "a" * 40
        tree_sha256 = "b" * 64
        inventory_path = registry_root / ".bureau-runtime-snapshot.json"
        inventory_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "bureau_registry_snapshot",
                    "source_commit": source_commit,
                    "tree_sha256": tree_sha256,
                    "paths": ["registry/queue.json"],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest_path = runtime_root / "deployment-manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kind": "bureau_runtime_deployment",
                    "source_commit": source_commit,
                    "canonical_registry_root": str(registry_root),
                    "canonical_registry_inventory_path": str(inventory_path),
                    "canonical_registry_tree_sha256": tree_sha256,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest_sha256 = (
            __import__("hashlib").sha256(manifest_path.read_bytes()).hexdigest()
        )
        launcher_path = self.root / "bin/bureau"
        launcher_path.parent.mkdir()
        launcher_path.write_text(
            "#!/usr/bin/env python3\n"
            f"manifest_path = Path('{manifest_path}')\n"
            f"expected_manifest_sha256 = '{manifest_sha256}'\n",
            encoding="utf-8",
        )
        launcher_path.chmod(0o700)
        return runtime_root, launcher_path, manifest_path, source_commit, tree_sha256

    def test_managed_runtime_binding_binds_manifest_and_registry_snapshot(self) -> None:
        runtime_root, launcher, manifest, source_commit, tree_sha256 = (
            self._managed_runtime_fixture()
        )
        with (
            mock.patch.object(
                intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
            ),
            mock.patch.object(intake, "BUREAU_MANAGED_LAUNCHER", launcher),
            mock.patch.object(intake, "BUREAU_DEPLOYMENT_MANIFEST", manifest),
        ):
            binding = intake._managed_runtime_binding()
            intake._assert_managed_runtime_unchanged(binding)
        self.assertEqual(binding["source_commit"], source_commit)
        self.assertEqual(binding["registry_tree_sha256"], tree_sha256)
        self.assertEqual(binding["launcher_path"], launcher)

    def test_managed_runtime_binding_rejects_launcher_manifest_digest_drift(
        self,
    ) -> None:
        runtime_root, launcher, manifest, _, _ = self._managed_runtime_fixture()
        launcher.write_text(
            "#!/usr/bin/env python3\n"
            f"manifest_path = Path('{manifest}')\n"
            f"expected_manifest_sha256 = '{'0' * 64}'\n",
            encoding="utf-8",
        )
        launcher.chmod(0o700)
        with (
            mock.patch.object(
                intake.bureau_runtime, "BUREAU_RUNTIME_ROOT", runtime_root
            ),
            mock.patch.object(intake, "BUREAU_MANAGED_LAUNCHER", launcher),
            mock.patch.object(intake, "BUREAU_DEPLOYMENT_MANIFEST", manifest),
        ):
            with self.assertRaisesRegex(
                intake.bureau_runtime.BureauLeaseContractError,
                "manifest-digest-mismatch",
            ):
                intake._managed_runtime_binding()

    def test_candidate_record_writes_digest_bound_private_request(self) -> None:
        request = {
            "schema_version": 1,
            "idempotency_key": "conversation:1",
            "title": "Record candidate",
            "source_kind": "conversation",
            "desired_outcome": "Create one task",
        }
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={
                "kind": "bureau_candidate_record_result",
                "status": "recorded",
            },
        ) as invoke:
            result = intake.grabowski_bureau_candidate_record(request)
        request_path = Path(invoke.call_args.args[0][-1])
        self.assertEqual(json.loads(request_path.read_text()), request)
        self.assertEqual(request_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.artifacts.stat().st_mode & 0o777, 0o700)
        self.assertEqual(result["status"], "recorded")
        self.assertEqual(request_path.stem, result["adapter_request_sha256"])

    def test_candidate_assess_requires_exactly_one_selector(self) -> None:
        with self.assertRaises(ValueError):
            intake.grabowski_bureau_candidate_assess()
        with self.assertRaises(ValueError):
            intake.grabowski_bureau_candidate_assess("candidate-a", 1)
        with mock.patch.object(
            intake,
            "_invoke_bureau",
            return_value={"kind": "bureau_candidate_assessment"},
        ) as invoke:
            result = intake.grabowski_bureau_candidate_assess(
                candidate_id="candidate-a", initiative="INIT", task_id="INIT-T001"
            )
        self.assertEqual(result["kind"], "bureau_candidate_assessment")
        self.assertIn("--candidate-id", invoke.call_args.args[0])

    def test_task_propose_is_adapter_idempotent(self) -> None:
        task = {"schema_version": 1, "id": "INIT-T099"}

        def invoke(arguments, **_kwargs):
            if "--write-plan" in arguments:
                plan = Path(arguments[arguments.index("--write-plan") + 1])
                plan.write_text(
                    json.dumps(
                        {
                            "publishing_task_id": "INIT-T001",
                            "proposal_sha256": "a" * 64,
                        }
                    )
                    + "\n"
                )
                return {"kind": "bureau_task_proposal_result", "status": "proposed"}
            return {
                "kind": "bureau_task_publication_preview",
                "status": "ready",
                "proposal_sha256": "a" * 64,
            }

        with mock.patch.object(intake, "_invoke_bureau", side_effect=invoke) as adapter:
            first = intake.grabowski_bureau_task_propose(
                task,
                "INIT-T001",
                candidate_id="candidate-a",
                registry_root=str(self.root),
            )
            second = intake.grabowski_bureau_task_propose(
                task,
                "INIT-T001",
                candidate_id="candidate-a",
                registry_root=str(self.root),
            )
        self.assertEqual(adapter.call_count, 2)
        self.assertEqual(first["adapter_proposal_id"], second["adapter_proposal_id"])
        self.assertFalse(first["idempotent_adapter_replay"])
        self.assertTrue(second["idempotent_adapter_replay"])

    def _write_proposal(self, proposal_id: str = "b" * 64) -> Path:
        directory = self.artifacts / "proposals" / proposal_id
        directory.mkdir(parents=True)
        (directory / "plan.json").write_text(
            json.dumps(
                {
                    "publishing_task_id": "INIT-T001",
                    "proposal_sha256": "c" * 64,
                }
            )
            + "\n"
        )
        return directory

    def test_publish_acquires_exact_bound_resources_and_releases_on_success(
        self,
    ) -> None:
        proposal_id = "b" * 64
        directory = self._write_proposal(proposal_id)
        keys = [
            "path:/home/alex/repos/bureau/.bureau-scopes/registry-publication",
            "path:/home/alex/repos/bureau/registry/tasks/INIT-T099.json",
        ]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "required_resource_keys": keys,
        }

        def invoke(arguments, **_kwargs):
            receipt = Path(arguments[arguments.index("--receipt") + 1])
            receipt.write_text(
                json.dumps({"kind": "bureau_task_publication_receipt"}) + "\n"
            )
            return {"kind": "bureau_task_publication_receipt", "status": "published"}

        acquired = {
            "expires_at_unix": 200,
            "bureau_contract": {"kind": "bureau_lease_diagnostics"},
        }
        released = {"released": [{"resource_key": key} for key in keys]}
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(
                intake.resources, "acquire_resources", return_value=acquired
            ) as acquire,
            mock.patch.object(
                intake.resources, "release_resources", return_value=released
            ) as release,
            mock.patch.object(intake, "_invoke_bureau", side_effect=invoke),
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root), lease_ttl_seconds=240
            )
        metadata = acquire.call_args.kwargs["metadata"]
        self.assertEqual(acquire.call_args.args[1], keys)
        self.assertEqual(metadata["task_id"], "INIT-T001")
        self.assertEqual(metadata["operation"], "registry-publication")
        self.assertEqual(metadata["proposal_sha256"], "c" * 64)
        self.assertEqual(acquire.call_args.kwargs["ttl_seconds"], 240)
        release.assert_called_once()
        self.assertTrue(result["leases_released"])
        self.assertTrue((directory / "publication-receipt.json").exists())

    def test_publish_existing_receipt_replays_without_leases(self) -> None:
        proposal_id = "e" * 64
        directory = self._write_proposal(proposal_id)
        (directory / "publication-receipt.json").write_text(
            json.dumps({"kind": "bureau_task_publication_receipt"}) + "\n"
        )
        with (
            mock.patch.object(
                intake,
                "_invoke_bureau",
                return_value={
                    "kind": "bureau_task_publication_receipt",
                    "status": "published",
                    "idempotent_replay": True,
                },
            ) as invoke,
            mock.patch.object(intake.resources, "acquire_resources") as acquire,
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        acquire.assert_not_called()
        self.assertEqual(invoke.call_count, 1)
        self.assertFalse(result["leases_acquired"])
        self.assertTrue(result["idempotent_adapter_replay"])

    def test_publish_reconciles_ambiguity_from_created_receipt(self) -> None:
        proposal_id = "f" * 64
        self._write_proposal(proposal_id)
        keys = ["path:/a", "path:/b"]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "required_resource_keys": keys,
        }
        calls = 0

        def invoke(arguments, **_kwargs):
            nonlocal calls
            calls += 1
            receipt = Path(arguments[arguments.index("--receipt") + 1])
            if calls == 1:
                receipt.write_text(
                    json.dumps({"kind": "bureau_task_publication_receipt"}) + "\n"
                )
                return {
                    "kind": "bureau_operator_intake_failure",
                    "code": "publication-unclear",
                    "effect_started": True,
                    "ambiguity": True,
                }
            return {
                "kind": "bureau_task_publication_receipt",
                "status": "published",
                "ambiguity": False,
            }

        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(
                intake.resources,
                "acquire_resources",
                return_value={"expires_at_unix": 200, "bureau_contract": {}},
            ),
            mock.patch.object(
                intake.resources,
                "release_resources",
                return_value={"released": [{"resource_key": key} for key in keys]},
            ) as release,
            mock.patch.object(intake, "_invoke_bureau", side_effect=invoke),
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        self.assertEqual(calls, 2)
        release.assert_called_once()
        self.assertEqual(result["ambiguity_reconciled"], "receipt-replay")
        self.assertTrue(result["receipt_readback_attempted"])
        self.assertTrue(result["leases_released"])

    def test_publish_retains_leases_when_bureau_reports_ambiguity(self) -> None:
        proposal_id = "d" * 64
        self._write_proposal(proposal_id)
        keys = ["path:/a", "path:/b"]
        preview = {
            "kind": "bureau_task_publication_preview",
            "status": "ready",
            "required_resource_keys": keys,
        }
        with (
            mock.patch.object(
                intake, "grabowski_bureau_task_publish_preview", return_value=preview
            ),
            mock.patch.object(
                intake.resources,
                "acquire_resources",
                return_value={"expires_at_unix": 200, "bureau_contract": {}},
            ),
            mock.patch.object(intake.resources, "release_resources") as release,
            mock.patch.object(
                intake,
                "_invoke_bureau",
                return_value={
                    "kind": "bureau_operator_intake_failure",
                    "code": "publication-unclear",
                    "effect_started": True,
                    "ambiguity": True,
                    "required_readback": ["remote_branch", "pull_request"],
                },
            ),
        ):
            result = intake.grabowski_bureau_task_publish(
                proposal_id, registry_root=str(self.root)
            )
        release.assert_not_called()
        self.assertFalse(result["leases_released"])
        self.assertTrue(result["ambiguity"])


if __name__ == "__main__":
    unittest.main()

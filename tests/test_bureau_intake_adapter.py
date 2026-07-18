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
        runtime = {
            "python_launcher": Path("/runtime/python"),
            "module_paths": {"bureau.cli": Path("/runtime/bureau/cli.py")},
            "package_files": {},
            "package_paths": {},
            "package_identities": {},
        }
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
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
        runtime = {
            "python_launcher": Path("/runtime/python"),
            "module_paths": {"bureau.cli": Path("/runtime/bureau/cli.py")},
            "package_files": {},
            "package_paths": {},
            "package_identities": {},
        }
        with (
            mock.patch.object(
                intake.bureau_runtime, "_contract_runtime", return_value=runtime
            ),
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

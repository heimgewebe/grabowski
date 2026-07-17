from __future__ import annotations

from pathlib import Path
import unittest
from unittest.mock import patch

from tests.test_grips import (
    CAPTAIN_HEAD,
    FakeGh,
    FakeGit,
    captain_action,
    captain_execution_intent,
    captain_parameters,
)

import grabowski_grips as grips
import grabowski_task_attention as attention


SOURCE_PATH = "/home/alex/repos/.grabowski-worktrees/deploy-source-v1"
SOURCE_OWNER = "operator-deploy-source-v1"
SOURCE_SHA = "e" * 64


class DeploySourceSurfaceTests(unittest.TestCase):
    def test_runtime_deploy_check_binds_explicit_source_pair(self) -> None:
        preflight = {
            "adapter": "grabowski-self",
            "repository": SOURCE_PATH,
            "runner": f"{SOURCE_PATH}/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": CAPTAIN_HEAD,
            "source_kind": "detached-worktree",
            "source_identity_sha256": SOURCE_SHA,
            "source_lease_resource_key": f"path:{SOURCE_PATH}",
            "source_lease_metadata_sha256": "f" * 64,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        parameters = {
            "adapter": "grabowski-self",
            "expected_head": CAPTAIN_HEAD,
            "source_repository": SOURCE_PATH,
            "source_lease_owner_id": SOURCE_OWNER,
        }
        with patch.object(
            grips, "_runtime_deploy_self_preflight", return_value=preflight
        ) as check:
            result = grips.grip_run("runtime-deploy-check", parameters)

        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual(SOURCE_SHA, result["output"]["source_identity_sha256"])
        check.assert_called_once_with(CAPTAIN_HEAD, SOURCE_PATH, SOURCE_OWNER)

    def test_runtime_deploy_check_rejects_partial_or_relative_source_pair(self) -> None:
        for parameters in (
            {
                "adapter": "grabowski-self",
                "expected_head": CAPTAIN_HEAD,
                "source_repository": SOURCE_PATH,
            },
            {
                "adapter": "grabowski-self",
                "expected_head": CAPTAIN_HEAD,
                "source_repository": "relative/source",
                "source_lease_owner_id": SOURCE_OWNER,
            },
            {
                "adapter": "grabowski-self",
                "expected_head": CAPTAIN_HEAD,
                "source_repository": SOURCE_PATH,
                "source_lease_owner_id": "owner with spaces",
            },
        ):
            with self.subTest(parameters=parameters), patch.object(
                grips, "_runtime_deploy_self_preflight"
            ) as check:
                result = grips.grip_run("runtime-deploy-check", parameters)
                self.assertEqual("blocked", result["receipt"]["status"])
                check.assert_not_called()

    def test_mechanic_target_rejects_source_pair_drift(self) -> None:
        parameters = {
            "adapter": "grabowski-self",
            "expected_head": CAPTAIN_HEAD,
            "source_repository": SOURCE_PATH,
            "source_lease_owner_id": SOURCE_OWNER,
        }
        target = {
            "adapter": "grabowski-self",
            "expected_head": CAPTAIN_HEAD,
            "service": "grabowski-mcp",
            "runtime_target": "heim-pc",
            "source_repository": SOURCE_PATH,
            "source_lease_owner_id": "other-owner",
        }
        with self.assertRaisesRegex(
            grips.GripPreflightError, "source_lease_owner_id must match"
        ):
            grips._validate_mechanic_target_matches_parameters(
                "runtime-deploy-check", parameters, target, index=0
            )

    def test_captain_schedules_explicit_detached_source_and_binds_identity(self) -> None:
        target = {
            "service": "grabowski-mcp",
            "runtime_target": "heim-pc",
            "adapter": "grabowski-self",
            "source_repository": SOURCE_PATH,
            "source_lease_owner_id": SOURCE_OWNER,
        }
        action = captain_action(
            action="runtime-deploy",
            target=target,
            scope={
                "allowed_effects": ["schedule one verified Grabowski self-deployment"],
                "forbidden_effects": ["arbitrary shell", "other services", "other hosts"],
                "boundaries": "single local Grabowski runtime from one leased detached source",
                "max_targets": 1,
            },
            risk={
                "risk_level": "high",
                "irreversibility": "reversible",
                "recovery_path": "inspect the scheduled job and roll back to the previous release",
            },
            receipt_path="receipts/captain/runtime-deploy-detached.json",
        )
        parameters = captain_parameters(
            [action],
            trusted_owner_mode=True,
            autonomy_policy=grips.CAPTAIN_TRUSTED_OWNER_AUTONOMY_POLICY,
            allow_execution=True,
            source_repository=SOURCE_PATH,
            source_lease_owner_id=SOURCE_OWNER,
        )
        parameters.pop("human_authorization")
        parameters.pop("execution_authority")
        parameters["execution_intent"] = captain_execution_intent(parameters)
        preflight = {
            "adapter": "grabowski-self",
            "repository": SOURCE_PATH,
            "runner": f"{SOURCE_PATH}/tools/run_scheduled_deploy.py",
            "job_root": str(Path.home() / ".local/state/grabowski/jobs"),
            "job_prefix": "grabowski-job-",
            "expected_head": CAPTAIN_HEAD,
            "source_kind": "detached-worktree",
            "source_identity_sha256": SOURCE_SHA,
            "source_lease_resource_key": f"path:{SOURCE_PATH}",
            "source_lease_metadata_sha256": "f" * 64,
            "target": {"service": "grabowski-mcp", "runtime_target": "heim-pc"},
            "ready": True,
        }
        unit = "grabowski-job-abcdef012345"
        job_dir = Path(preflight["job_root"]) / unit
        schedule = {
            "scheduled": True,
            "already_scheduled": False,
            "expected_head": CAPTAIN_HEAD,
            "requested_delay_seconds": 8,
            "delay_seconds": 8,
            "unit": unit,
            "argv_sha256": "d" * 64,
            "source_identity_sha256": SOURCE_SHA,
            "source_identity": {"identity_sha256": SOURCE_SHA},
            "metadata_path": str(job_dir / "metadata.json"),
            "stdout_path": str(job_dir / "stdout.log"),
            "stderr_path": str(job_dir / "stderr.log"),
            "expected_connector_disconnect": True,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }
        with patch.object(
            grips, "_runtime_deploy_self_preflight", return_value=preflight
        ) as check, patch.object(
            grips, "_runtime_deploy_self_schedule", return_value=schedule
        ) as scheduler, patch.object(
            grips, "_runtime_deploy_self_expected_argv_sha256", return_value="d" * 64
        ):
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )

        self.assertEqual("passed", result["receipt"]["status"])
        execution = result["output"]["executions"][0]
        self.assertEqual(SOURCE_SHA, execution["next_verification"]["source_identity_sha256"])
        check.assert_called_once_with(CAPTAIN_HEAD, SOURCE_PATH, SOURCE_OWNER)
        scheduler.assert_called_once_with(CAPTAIN_HEAD, 8, SOURCE_PATH, SOURCE_OWNER)

    def test_captain_blocks_source_target_parameter_drift_before_schedule(self) -> None:
        action = captain_action(
            action="runtime-deploy",
            target={
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
                "adapter": "grabowski-self",
                "source_repository": SOURCE_PATH,
                "source_lease_owner_id": SOURCE_OWNER,
            },
        )
        parameters = captain_parameters(
            [action],
            source_repository=SOURCE_PATH,
            source_lease_owner_id="different-owner",
        )
        with patch.object(grips, "_runtime_deploy_self_preflight") as check, patch.object(
            grips, "_runtime_deploy_self_schedule"
        ) as scheduler:
            result = grips.grip_run(
                "captain-run",
                parameters,
                profile="captain",
                allow_mutation=True,
                command_runner=FakeGit(),
                github_runner=FakeGh(),
            )
        self.assertEqual("blocked", result["receipt"]["status"])
        check.assert_not_called()
        scheduler.assert_not_called()


class TaskAttentionGripTests(unittest.TestCase):
    def _decision_parameters(self) -> dict[str, object]:
        return {
            "task_id": "a" * 24,
            "decision": "deferred",
            "expected_attempt": 3,
            "expected_unit": f"grabowski-task-{'a' * 24}-a3.service",
            "expected_authoritative_unit": f"grabowski-task-{'a' * 24}-a3.service",
            "expected_argv_sha256": "b" * 64,
            "expected_execution_envelope_sha256": None,
            "outcome_receipt_sha256": "c" * 64,
            "authority": "operator:alex",
            "evidence_ref": "bureau:event:597",
        }

    def test_decision_grip_passes_receipt_bound_result(self) -> None:
        output = {
            "created": True,
            "replayed": False,
            "task_binding": {"argv_sha256": "b" * 64},
            "decision": "deferred",
            "outcome_receipt_sha256": "c" * 64,
            "material_sha256": "d" * 64,
            "receipt_sha256": "e" * 64,
            "file_sha256": "f" * 64,
        }
        with patch.object(attention, "record_decision", return_value=output):
            result = grips.grip_run(
                "task-attention-decision",
                self._decision_parameters(),
                allow_mutation=True,
            )
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual("deferred", result["output"]["decision"])

    def test_decision_grip_conflict_is_blocked(self) -> None:
        with patch.object(
            attention,
            "record_decision",
            side_effect=attention.TaskAttentionConflictError("different material"),
        ):
            result = grips.grip_run(
                "task-attention-decision",
                self._decision_parameters(),
                allow_mutation=True,
            )
        self.assertEqual("blocked", result["receipt"]["status"])
        self.assertEqual(["attention_decision_conflict"], result["output"]["blocked_reasons"])

    def test_reconciliation_grip_is_read_only_and_exposes_conservative_counts(self) -> None:
        output = {
            "schema_version": 1,
            "records": [],
            "classification_counts": {
                "actionable": 0,
                "outcome_unknown": 0,
                "decision_closed": 0,
                "decision_deferred": 0,
                "decision_superseded": 0,
                "invalid_evidence": 0,
            },
            "total_attention": 0,
            "pagination": {"returned": 0, "limit": 20, "has_more": False, "next_cursor": None},
        }
        with patch.object(attention, "reconcile_attention", return_value=output):
            result = grips.grip_run("task-attention-reconciliation", {"limit": 20})
        self.assertEqual("passed", result["receipt"]["status"])
        self.assertEqual(0, result["output"]["total_attention"])


if __name__ == "__main__":
    unittest.main()

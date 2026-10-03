from __future__ import annotations

from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


class _FakeFastMCP:
    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def tool(self, *args: object, **kwargs: object):
        del args, kwargs
        return lambda function: function


class _FakeToolAnnotations:
    def __init__(self, **kwargs: object) -> None:
        self.values = kwargs


if "mcp" not in sys.modules:
    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp = types.ModuleType("mcp.server.fastmcp")
    fake_types = types.ModuleType("mcp.types")
    fake_fastmcp.FastMCP = _FakeFastMCP
    fake_types.ToolAnnotations = _FakeToolAnnotations
    sys.modules["mcp"] = fake_mcp
    sys.modules["mcp.server"] = fake_server
    sys.modules["mcp.server.fastmcp"] = fake_fastmcp
    sys.modules["mcp.types"] = fake_types

import grabowski_grips as grips  # noqa: E402


class RuntimeDeployScheduleReceiptTests(unittest.TestCase):
    def test_scheduler_auto_source_non_object_preserves_unknown_mutation_outcome(
        self,
    ) -> None:
        preflight = {
            "resolution_mode": "scheduler-auto-source",
            "ready": True,
        }
        action = {
            "target": {
                "adapter": "grabowski-self",
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
            }
        }

        with patch.object(
            grips,
            "_runtime_deploy_expected_head",
            return_value="a" * 40,
        ), patch.object(
            grips,
            "_runtime_deploy_delay_seconds",
            return_value=8,
        ), patch.object(
            grips,
            "_runtime_deploy_source_parameters",
            return_value=(None, None),
        ), patch.object(
            grips,
            "_captain_runtime_deploy_target_errors",
            return_value=[],
        ), patch.object(
            grips,
            "_runtime_deploy_self_preflight",
            return_value=preflight,
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule",
            return_value=["not", "an", "object"],
        ):
            result = grips._run_captain_runtime_deploy(action, {})

        self.assertTrue(result["execution_attempted"])
        self.assertTrue(result["execution_invoked"])
        self.assertTrue(result["command_returned"])
        self.assertTrue(result["mutation_outcome_unknown"])
        self.assertTrue(result["local_mutation_outcome_unknown"])
        self.assertFalse(result["verification_passed"])
        self.assertIn(
            "runtime deploy scheduler returned non-object",
            result["verification_error"],
        )

    def test_bound_preflight_uses_scheduler_source_readback_after_race(self) -> None:
        expected = "a" * 40
        preflight = {
            "repository": "/home/alex/repos/grabowski",
            "runner": "/home/alex/repos/grabowski/tools/run_scheduled_deploy.py",
            "job_root": "/home/alex/.local/state/grabowski/jobs",
            "job_prefix": "grabowski-job-",
            "source_kind": "canonical-main",
            "source_identity_sha256": "c" * 64,
            "ready": True,
        }
        source_repository = (
            "/home/alex/repos/.grabowski-deploy-worktrees/"
            "auto-current-main-aaaaaaaaaaaa-abc123def456"
        )
        source_readback = {
            "repository": source_repository,
            "runner": f"{source_repository}/tools/run_scheduled_deploy.py",
            "source_kind": "detached-worktree",
            "source_identity_sha256": "d" * 64,
            "source_lease_resource_key": f"path:{source_repository}",
            "source_lease_metadata_sha256": "e" * 64,
        }
        schedule = {
            "delay_seconds": 8,
            "unit": "grabowski-job-race00000001",
            "already_scheduled": False,
            "status_tool": "grabowski_job_status",
            "logs_tool": "grabowski_job_logs",
        }
        action = {
            "target": {
                "adapter": "grabowski-self",
                "service": "grabowski-mcp",
                "runtime_target": "heim-pc",
            }
        }

        with patch.object(
            grips,
            "_runtime_deploy_expected_head",
            return_value=expected,
        ), patch.object(
            grips,
            "_runtime_deploy_delay_seconds",
            return_value=8,
        ), patch.object(
            grips,
            "_runtime_deploy_source_parameters",
            return_value=(None, None),
        ), patch.object(
            grips,
            "_captain_runtime_deploy_target_errors",
            return_value=[],
        ), patch.object(
            grips,
            "_runtime_deploy_self_preflight",
            return_value=preflight,
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule",
            return_value=schedule,
        ), patch.object(
            grips,
            "_runtime_deploy_self_schedule_source_preflight",
            return_value=source_readback,
        ) as source_check, patch.object(
            grips,
            "_runtime_deploy_self_expected_argv_sha256",
            return_value="f" * 64,
        ) as hash_check, patch.object(
            grips,
            "_runtime_deploy_schedule_errors",
            return_value=[],
        ):
            result = grips._run_captain_runtime_deploy(action, {})

        self.assertTrue(result["verification_passed"])
        self.assertEqual(source_readback, result["source_readback"])
        source_check.assert_called_once_with(schedule, expected)
        bound_preflight = hash_check.call_args.args[0]
        self.assertEqual(source_repository, bound_preflight["repository"])
        self.assertEqual("detached-worktree", bound_preflight["source_kind"])
        self.assertEqual("d" * 64, bound_preflight["source_identity_sha256"])



if __name__ == "__main__":
    unittest.main()

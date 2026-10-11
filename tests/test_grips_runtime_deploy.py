from __future__ import annotations

from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

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
import grabowski_self_deploy as real_deploy  # noqa: E402


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



class RuntimeReleaseSourceAdmissionTests(unittest.TestCase):
    @staticmethod
    def _git_success(output: str) -> dict[str, object]:
        return {
            "returncode": 0,
            "timed_out": False,
            "stdout": output,
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    @staticmethod
    def _deployed() -> dict[str, object]:
        return {
            "release_id": "existing-protected-release",
            "repo_head": "a" * 40,
            "completion_status": "complete",
            "runtime_binding_valid": True,
            "artifact_integrity_valid": True,
            "provenance_valid": True,
        }

    @staticmethod
    def _serving() -> dict[str, object]:
        return {
            "matches_deployed_manifest": True,
            "process_release_id": "existing-protected-release",
            "process_repo_head": "a" * 40,
        }

    def test_critical_source_change_requires_authentic_release_admission(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("src/grabowski_agent_role.py\x00tests/test_agent_role_grok.py\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "release.*admission"):
                deploy._require_release_source_admission("b" * 40)

    def test_docs_only_delta_has_no_release_review_bypass_of_runtime_source(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/guide.md\x00"),
                    self._git_success(
                        ":100644 100644 " + "1" * 40 + " " + "2" * 40 + " M\x00docs/guide.md\x00"
                    ),
                ],
            ),
        ):
            record = deploy._require_release_source_admission("b" * 40)
        self.assertEqual("non-runtime-documentation", record["status"])

    def test_missing_serving_process_provenance_blocks(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value={"matches_deployed_manifest": False}),
            patch.object(deploy, "_git_result") as git_read,
        ):
            with self.assertRaisesRegex(RuntimeError, "serving"):
                deploy._require_release_source_admission("b" * 40)
        git_read.assert_not_called()

    def test_direct_scheduler_rejects_before_github_or_local_mutation(self) -> None:
        import grabowski_self_deploy as deploy
        with (
            patch.object(deploy, "_require_release_source_admission", side_effect=RuntimeError("release admission missing")),
            patch.object(deploy, "_fresh_public_github_main") as remote,
            patch.object(deploy, "inflight_runtime_job_evidence") as inflight,
        ):
            with self.assertRaisesRegex(RuntimeError, "release admission missing"):
                deploy._grabowski_runtime_deploy_schedule_impl(
                    "b" * 40, local_mutation_tracker={}
                )
        remote.assert_not_called()
        inflight.assert_not_called()

    def test_captain_runtime_deploy_marks_review_gate_blocked(self) -> None:
        # Exercise the Captain policy seam without import-order effects from
        # the old scheduler fixture's synthetic modules.
        fake_deploy = types.ModuleType("grabowski_self_deploy")
        admission = Mock(side_effect=RuntimeError("release admission missing"))
        fake_deploy._require_release_source_admission = admission
        with patch.dict(sys.modules, {"grabowski_self_deploy": fake_deploy}):
            gate = grips._captain_independent_review_gate(
                {"expected_head": "b" * 40},
                [
                    {
                        "action": "runtime-deploy",
                        "target": {
                            "repo": "heimgewebe/grabowski",
                            "runtime_target": "heim-pc",
                            "adapter": "grabowski-self",
                        },
                    }
                ],
            )
        self.assertEqual("blocked", gate["status"])
        self.assertIn("release", str(gate.get("details", gate.get("reason", ""))))
        admission.assert_called_once_with("b" * 40, release_review_pr=None, captain_preview=True)


    def test_source_diff_without_explicit_transport_completeness_blocks(self) -> None:
        deploy = real_deploy
        observed = self._git_success("docs/guide.md\x00")
        del observed["stdout_truncated"]
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(deploy, "_git_result", side_effect=[self._git_success(""), observed]),
        ):
            with self.assertRaisesRegex(RuntimeError, "complete source diff"):
                deploy._require_release_source_admission("b" * 40)

    def test_source_ancestor_missing_explicit_zero_exit_blocks(self) -> None:
        deploy = real_deploy
        ancestor = self._git_success("")
        ancestor["returncode"] = False
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(deploy, "_git_result", side_effect=[ancestor]) as read,
        ):
            with self.assertRaisesRegex(RuntimeError, "source ancestry"):
                deploy._require_release_source_admission("b" * 40)
        read.assert_called_once()

    def test_source_path_escape_from_docs_prefix_blocks(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/../src/grabowski_agent_role.py\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "source paths"):
                deploy._require_release_source_admission("b" * 40)

    def test_truncated_and_unterminated_path_output_blocks(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/readme.md"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "source path boundary"):
                deploy._require_release_source_admission("b" * 40)


    def test_redacted_documentation_path_cannot_grant_release_admission(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/<REDACTED>\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "source paths"):
                deploy._require_release_source_admission("b" * 40)

    def test_executable_script_inside_docs_does_not_get_documentation_exemption(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(
                deploy,
                "_git_result",
                side_effect=[
                    self._git_success(""),
                    self._git_success("docs/run_deploy.sh\x00"),
                ],
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "release review admission missing"):
                deploy._require_release_source_admission("b" * 40)



if __name__ == "__main__":
    unittest.main()
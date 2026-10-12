from __future__ import annotations

from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
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



    def test_public_main_readback_validates_exact_git_oid_width(self) -> None:
        import grabowski_self_deploy as deploy
        for width in (40, 64):
            with self.subTest(valid_width=width):
                head = "a" * width
                body = json.dumps({
                    "ref": deploy.PUBLIC_GITHUB_MAIN_REF,
                    "object": {"type": "commit", "sha": head},
                }).encode()
                completed = types.SimpleNamespace(
                    returncode=0, stdout=body, stderr=b""
                )
                with patch.object(deploy.subprocess, "run", return_value=completed):
                    self.assertEqual(head, deploy._fresh_public_github_main(head))
        for expected, observed in (
            ("a" * 64, "b" * 40),
            ("a" * 40, "b" * 64),
            ("a" * 64, "b" * 63),
        ):
            with self.subTest(expected=len(expected), observed=len(observed)):
                body = json.dumps({
                    "ref": deploy.PUBLIC_GITHUB_MAIN_REF,
                    "object": {"type": "commit", "sha": observed},
                }).encode()
                completed = types.SimpleNamespace(
                    returncode=0, stdout=body, stderr=b""
                )
                with patch.object(deploy.subprocess, "run", return_value=completed):
                    with self.assertRaisesRegex(RuntimeError, "invalid commit"):
                        deploy._fresh_public_github_main(expected)
        with patch.object(deploy.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "full Git"):
                deploy._fresh_public_github_main("a" * 63)
        run.assert_not_called()

    def test_sha256_documentation_exemption_checks_full_git_raw_mode_oids(self) -> None:
        deploy = real_deploy
        metadata = self._deployed()
        process = self._serving()
        metadata["repo_head"] = "a" * 64
        process["process_repo_head"] = "a" * 64
        raw = ":100644 100644 " + "1" * 64 + " " + "2" * 64 + " M\x00docs/guide.md\x00"
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=metadata),
            patch.object(deploy.serving_process, "identity", return_value=process),
            patch.object(deploy, "_git_result", side_effect=[
                self._git_success(""),
                self._git_success("docs/guide.md\x00"),
                self._git_success(raw),
            ]) as git,
        ):
            result = deploy._require_release_source_admission("b" * 64)
        self.assertEqual("non-runtime-documentation", result["status"])
        self.assertIn("--abbrev=64", git.call_args_list[2].args)
        self.assertNotIn("--abbrev=40", git.call_args_list[2].args)

    def test_sha256_documentation_exemption_rejects_mixed_raw_mode_oids(self) -> None:
        deploy = real_deploy
        metadata = self._deployed()
        process = self._serving()
        metadata["repo_head"] = "a" * 64
        process["process_repo_head"] = "a" * 64
        raw = ":100644 100644 " + "1" * 40 + " " + "2" * 64 + " M\x00docs/guide.md\x00"
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=metadata),
            patch.object(deploy.serving_process, "identity", return_value=process),
            patch.object(deploy, "_git_result", side_effect=[
                self._git_success(""),
                self._git_success("docs/guide.md\x00"),
                self._git_success(raw),
            ]),
        ):
            with self.assertRaisesRegex(RuntimeError, "documentation Git object formats differ"):
                deploy._require_release_source_admission("b" * 64)

    def test_source_admission_rejects_inconsistent_git_object_formats_before_git(self) -> None:
        deploy = real_deploy
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=self._deployed()),
            patch.object(deploy.serving_process, "identity", return_value=self._serving()),
            patch.object(deploy, "_git_result") as git,
        ):
            with self.assertRaisesRegex(RuntimeError, "object formats"):
                deploy._require_release_source_admission("b" * 64)
        git.assert_not_called()
        for width in (41, 52, 63, 65):
            with self.subTest(width=width), patch.object(deploy, "_git_result") as git:
                with self.assertRaisesRegex(RuntimeError, "exact target head"):
                    deploy._require_release_source_admission("b" * width)
                git.assert_not_called()

    def test_sha256_critical_release_review_receives_full_tree_oids(self) -> None:
        import grabowski_release_admission as review
        deploy = real_deploy
        metadata = self._deployed()
        process = self._serving()
        metadata["repo_head"] = "a" * 64
        process["process_repo_head"] = "a" * 64
        raw = ":100644 100644 " + "1" * 64 + " " + "2" * 64 + " M\x00src/a.py\x00"
        synthetic = {"status": "synthetic-review-callback-not-release-authority"}
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=metadata),
            patch.object(deploy.serving_process, "identity", return_value=process),
            patch.object(deploy, "_git_result", side_effect=[
                self._git_success(""),
                self._git_success("src/a.py\x00"),
                self._git_success(raw),
                self._git_success("1" * 64 + "\n"),
                self._git_success("2" * 64 + "\n"),
            ]) as git,
            patch.object(review, "validate_release", return_value=synthetic) as validate,
        ):
            self.assertIs(synthetic, deploy._require_release_source_admission(
                "b" * 64, release_review_pr=1480, captain_preview=True,
            ))
        self.assertEqual("a" * 64, validate.call_args.kwargs["serving_head"])
        self.assertEqual("b" * 64, validate.call_args.kwargs["target_head"])
        self.assertEqual("1" * 64, validate.call_args.kwargs["serving_tree"])
        self.assertEqual("2" * 64, validate.call_args.kwargs["target_tree"])
        self.assertEqual(hashlib.sha256(raw.encode()).hexdigest(), validate.call_args.kwargs["diff_sha256"])
        self.assertIn("--abbrev=64", git.call_args_list[2].args)
        self.assertNotIn("--abbrev=40", git.call_args_list[2].args)

    def test_sha256_critical_release_rejects_mixed_tree_before_review(self) -> None:
        import grabowski_release_admission as review
        deploy = real_deploy
        metadata = self._deployed()
        process = self._serving()
        metadata["repo_head"] = "a" * 64
        process["process_repo_head"] = "a" * 64
        with (
            patch.object(deploy.base, "_deployment_metadata", return_value=metadata),
            patch.object(deploy.serving_process, "identity", return_value=process),
            patch.object(deploy, "_git_result", side_effect=[
                self._git_success(""),
                self._git_success("src/a.py\x00"),
                self._git_success(":100644 100644 " + "1" * 64 + " " + "2" * 64 + " M\x00src/a.py\x00"),
                self._git_success("1" * 40 + "\n"),
            ]),
            patch.object(review, "validate_release") as validate,
        ):
            with self.assertRaisesRegex(RuntimeError, "exact source tree unavailable"):
                deploy._require_release_source_admission(
                    "b" * 64, release_review_pr=1480, captain_preview=True,
                )
        validate.assert_not_called()


    def test_git_raw_abbrev64_keeps_native_sha1_and_sha256_object_width(self) -> None:
        deploy = real_deploy
        with tempfile.TemporaryDirectory() as directory:
            for object_format, width in (("sha1", 40), ("sha256", 64)):
                with self.subTest(object_format=object_format):
                    repo = Path(directory) / object_format
                    repo.mkdir()
                    subprocess.run(
                        ["git", "init", "--quiet", f"--object-format={object_format}", str(repo)],
                        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    def git(*args: str) -> bytes:
                        result = subprocess.run(
                            [
                                "git", "-c", "core.hooksPath=/dev/null",
                                "-c", "user.name=OID Test",
                                "-c", "user.email=oid@example.org",
                                "-C", str(repo), *args,
                            ],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        )
                        return result.stdout

                    doc = repo / "docs" / "guide.md"
                    doc.parent.mkdir()
                    doc.write_text("before\n", encoding="utf-8")
                    git("add", "--", "docs/guide.md")
                    git("commit", "--quiet", "-m", "first")
                    base = git("rev-parse", "HEAD").decode().strip()
                    doc.write_text("after\n", encoding="utf-8")
                    git("add", "--", "docs/guide.md")
                    git("commit", "--quiet", "-m", "second")
                    head = git("rev-parse", "HEAD").decode().strip()
                    output = git(
                        "diff", "--raw", "--abbrev=64", "-z",
                        base, head, "--", "docs/guide.md",
                    ).decode()
                    header, path, _empty = output.split("\x00")
                    self.assertEqual("docs/guide.md", path)
                    parts = header.split()
                    self.assertEqual(5, len(parts))
                    self.assertEqual("M", parts[4])
                    self.assertEqual(width, len(parts[2]))
                    self.assertEqual(width, len(parts[3]))
                    self.assertTrue(
                        deploy._same_git_oid_format(parts[2], parts[3], base, head)
                    )


if __name__ == "__main__":
    unittest.main()
